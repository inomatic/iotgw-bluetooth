/*
 * Copyright (C) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <hardware/audio.h>
#include <hardware/hardware.h>
#include <audio_utils/resampler.h>

#include "../src/shared/util.h"
#include "sco-msg.h"
#include "ipc-common.h"
#include "hal-log.h"

#define AUDIO_STREAM_DEFAULT_RATE	44100
#define AUDIO_STREAM_SCO_RATE		8000
#define AUDIO_STREAM_DEFAULT_FORMAT	AUDIO_FORMAT_PCM_16_BIT

#define OUT_BUFFER_SIZE			2560
#define OUT_STREAM_FRAMES		2560

#define SOCKET_POLL_TIMEOUT_MS		500

static int listen_sk = -1;
static int ipc_sk = -1;

static int sco_fd = -1;
static uint16_t sco_mtu = 0;
static pthread_mutex_t sco_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_t ipc_th = 0;
static pthread_mutex_t sk_mutex = PTHREAD_MUTEX_INITIALIZER;

struct sco_audio_config {
	uint32_t rate;
	uint32_t channels;
	uint32_t frame_num;
	audio_format_t format;
};

struct sco_stream_out {
	struct audio_stream_out stream;

	struct sco_audio_config cfg;

	uint8_t *downmix_buf;
	uint8_t *cache;
	size_t cache_len;

	size_t samples;
	struct timespec start;

	struct resampler_itfe *resampler;
	int16_t *resample_buf;
	uint32_t resample_frame_num;
};

struct sco_stream_in {
	struct audio_stream_in stream;

	struct sco_audio_config cfg;
};

struct sco_dev {
	struct audio_hw_device dev;
	struct sco_stream_out *out;
	struct sco_stream_in *in;
};

/*
 * return the minimum frame numbers from resampling between BT stack's rate
 * and audio flinger's. For output stream, 'output' shall be true, otherwise
 * false for input streams at audio flinger side.
 */
static size_t get_resample_frame_num(uint32_t sco_rate, uint32_t rate,
						size_t frame_num, bool output)
{
	size_t resample_frames_num = frame_num * sco_rate / rate + output;

	DBG("resampler: sco_rate %d frame_num %zd rate %d resample frames %zd",
				sco_rate, frame_num, rate, resample_frames_num);

	return resample_frames_num;
}

/* SCO IPC functions */

static int sco_ipc_cmd(uint8_t service_id, uint8_t opcode, uint16_t len,
			void *param, size_t *rsp_len, void *rsp, int *fd)
{
	ssize_t ret;
	struct msghdr msg;
	struct iovec iv[2];
	struct ipc_hdr cmd;
	char cmsgbuf[CMSG_SPACE(sizeof(int))];
	struct ipc_status s;
	size_t s_len = sizeof(s);

	pthread_mutex_lock(&sk_mutex);

	if (ipc_sk < 0) {
		error("sco: Invalid cmd socket passed to sco_ipc_cmd");
		goto failed;
	}

	if (!rsp || !rsp_len) {
		memset(&s, 0, s_len);
		rsp_len = &s_len;
		rsp = &s;
	}

	memset(&msg, 0, sizeof(msg));
	memset(&cmd, 0, sizeof(cmd));

	cmd.service_id = service_id;
	cmd.opcode = opcode;
	cmd.len = len;

	iv[0].iov_base = &cmd;
	iv[0].iov_len = sizeof(cmd);

	iv[1].iov_base = param;
	iv[1].iov_len = len;

	msg.msg_iov = iv;
	msg.msg_iovlen = 2;

	ret = sendmsg(ipc_sk, &msg, 0);
	if (ret < 0) {
		error("sco: Sending command failed:%s", strerror(errno));
		goto failed;
	}

	/* socket was shutdown */
	if (ret == 0) {
		error("sco: Command socket closed");
		goto failed;
	}

	memset(&msg, 0, sizeof(msg));
	memset(&cmd, 0, sizeof(cmd));

	iv[0].iov_base = &cmd;
	iv[0].iov_len = sizeof(cmd);

	iv[1].iov_base = rsp;
	iv[1].iov_len = *rsp_len;

	msg.msg_iov = iv;
	msg.msg_iovlen = 2;

	if (fd) {
		memset(cmsgbuf, 0, sizeof(cmsgbuf));
		msg.msg_control = cmsgbuf;
		msg.msg_controllen = sizeof(cmsgbuf);
	}

	ret = recvmsg(ipc_sk, &msg, 0);
	if (ret < 0) {
		error("sco: Receiving command response failed:%s",
							strerror(errno));
		goto failed;
	}

	if (ret < (ssize_t) sizeof(cmd)) {
		error("sco: Too small response received(%zd bytes)", ret);
		goto failed;
	}

	if (cmd.service_id != service_id) {
		error("sco: Invalid service id (%u vs %u)", cmd.service_id,
								service_id);
		goto failed;
	}

	if (ret != (ssize_t) (sizeof(cmd) + cmd.len)) {
		error("sco: Malformed response received(%zd bytes)", ret);
		goto failed;
	}

	if (cmd.opcode != opcode && cmd.opcode != SCO_OP_STATUS) {
		error("sco: Invalid opcode received (%u vs %u)",
						cmd.opcode, opcode);
		goto failed;
	}

	if (cmd.opcode == SCO_OP_STATUS) {
		struct ipc_status *s = rsp;

		if (sizeof(*s) != cmd.len) {
			error("sco: Invalid status length");
			goto failed;
		}

		if (s->code == SCO_STATUS_SUCCESS) {
			error("sco: Invalid success status response");
			goto failed;
		}

		pthread_mutex_unlock(&sk_mutex);

		return s->code;
	}

	pthread_mutex_unlock(&sk_mutex);

	/* Receive auxiliary data in msg */
	if (fd) {
		struct cmsghdr *cmsg;

		*fd = -1;

		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
					cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level == SOL_SOCKET
					&& cmsg->cmsg_type == SCM_RIGHTS) {
				memcpy(fd, CMSG_DATA(cmsg), sizeof(int));
				break;
			}
		}

		if (*fd < 0)
			goto failed;
	}

	if (rsp_len)
		*rsp_len = cmd.len;

	return SCO_STATUS_SUCCESS;

failed:
	/* Some serious issue happen on IPC - recover */
	shutdown(ipc_sk, SHUT_RDWR);
	pthread_mutex_unlock(&sk_mutex);

	return SCO_STATUS_FAILED;
}

static int ipc_connect_sco(void)
{
	struct sco_rsp_connect rsp;
	size_t rsp_len = sizeof(rsp);
	int ret = SCO_STATUS_SUCCESS;

	DBG("");

	pthread_mutex_lock(&sco_mutex);

	if (sco_fd < 0) {
		ret = sco_ipc_cmd(SCO_SERVICE_ID, SCO_OP_CONNECT, 0, NULL,
						&rsp_len, &rsp, &sco_fd);

		/* Sometimes mtu returned is wrong */
		sco_mtu = /* rsp.mtu */ 48;
	}

	pthread_mutex_unlock(&sco_mutex);

	return ret;
}

/* Audio stream functions */

static void downmix_to_mono(struct sco_stream_out *out, const uint8_t *buffer,
							size_t frame_num)
{
	const int16_t *input = (const void *) buffer;
	int16_t *output = (void *) out->downmix_buf;
	size_t i;

	for (i = 0; i < frame_num; i++) {
		int16_t l = le16_to_cpu(get_unaligned(&input[i * 2]));
		int16_t r = le16_to_cpu(get_unaligned(&input[i * 2 + 1]));

		put_unaligned(cpu_to_le16((l + r) >> 1), &output[i]);
	}
}

static uint64_t timespec_diff_us(struct timespec *a, struct timespec *b)
{
	struct timespec res;

	res.tv_sec = a->tv_sec - b->tv_sec;
	res.tv_nsec = a->tv_nsec - b->tv_nsec;

	if (res.tv_nsec < 0) {
		res.tv_sec--;
		res.tv_nsec += 1000000000ll; /* 1sec */
	}

	return res.tv_sec * 1000000ll + res.tv_nsec / 1000ll;
}

static bool write_data(struct sco_stream_out *out, const uint8_t *buffer,
								size_t bytes)
{
	struct pollfd pfd;
	size_t len, written = 0;
	int ret;
	uint8_t *p;
	uint64_t audio_sent_us, audio_passed_us;

	pfd.fd = sco_fd;
	pfd.events = POLLOUT | POLLHUP | POLLNVAL;

	while (bytes > written) {
		struct timespec now;

		/* poll for sending */
		if (poll(&pfd, 1, SOCKET_POLL_TIMEOUT_MS) == 0) {
			DBG("timeout fd %d", sco_fd);
			return false;
		}

		if (pfd.revents & (POLLHUP | POLLNVAL)) {
			error("error fd %d, events 0x%x", sco_fd, pfd.revents);
			return false;
		}

		len = bytes - written > sco_mtu ? sco_mtu : bytes - written;

		clock_gettime(CLOCK_REALTIME, &now);
		/* Mark start of the stream */
		if (!out->samples)
			memcpy(&out->start, &now, sizeof(out->start));

		audio_sent_us = out->samples * 1000000ll / AUDIO_STREAM_SCO_RATE;
		audio_passed_us = timespec_diff_us(&now, &out->start);
		if ((int) (audio_sent_us - audio_passed_us) > 1500) {
			struct timespec timeout = {0,
						(audio_sent_us -
						 audio_passed_us) * 1000};
			DBG("Sleeping for %d ms",
					(int) (audio_sent_us - audio_passed_us));
			nanosleep(&timeout, NULL);
		} else if ((int)(audio_passed_us - audio_sent_us) > 50000) {
			DBG("\n\nResync\n\n");
			out->samples = 0;
			memcpy(&out->start, &now, sizeof(out->start));
		}

		if (out->cache_len) {
			DBG("First packet cache_len %zd", out->cache_len);
			memcpy(out->cache + out->cache_len, buffer,
						sco_mtu - out->cache_len);
			p = out->cache;
		} else {
			if (bytes - written >= sco_mtu)
				p = (void *) buffer + written;
			else {
				memcpy(out->cache, buffer + written,
							bytes - written);
				out->cache_len = bytes - written;
				DBG("Last packet, cache %zd bytes",
							bytes - written);
				written += bytes - written;
				continue;
			}
		}

		ret = write(sco_fd, p, len);
		if (ret > 0) {
			if (out->cache_len) {
				written = sco_mtu - out->cache_len;
				out->cache_len = 0;
			} else
				written += ret;

			out->samples += ret / 2;

			DBG("written %d samples %zd total %zd bytes",
					ret, out->samples, written);
			continue;
		}

		if (errno == EAGAIN) {
			ret = errno;
			warn("write failed (%d)", ret);
			continue;
		}

		if (errno != EINTR) {
			ret = errno;
			error("write failed (%d) fd %d bytes %zd", ret, sco_fd,
									bytes);
			return false;
		}
	}

	DBG("written %zd bytes", bytes);

	return true;
}

static ssize_t out_write(struct audio_stream_out *stream, const void *buffer,
								size_t bytes)
{
	struct sco_stream_out *out = (struct sco_stream_out *) stream;
	size_t frame_num = bytes / audio_stream_frame_size(&out->stream.common);
	size_t output_frame_num = frame_num;
	void *send_buf = out->downmix_buf;
	size_t total;

	DBG("write to fd %d bytes %zu", sco_fd, bytes);

	if (!out->downmix_buf) {
		error("sco: downmix buffer not initialized");
		return -1;
	}

	downmix_to_mono(out, buffer, frame_num);

	if (out->resampler) {
		int ret;

		/* limit resampler's output within what resample buf can hold */
		output_frame_num = out->resample_frame_num;

		ret = out->resampler->resample_from_input(out->resampler,
							send_buf,
							&frame_num,
							out->resample_buf,
							&output_frame_num);
		if (ret) {
			error("Failed to resample frames: %zd input %zd (%s)",
				frame_num, output_frame_num, strerror(ret));
			return -1;
		}

		send_buf = out->resample_buf;

		DBG("Resampled: frame_num %zd, output_frame_num %zd",
						frame_num, output_frame_num);
	}

	total = output_frame_num * sizeof(int16_t) * 1;

	DBG("total %zd", total);

	if (!write_data(out, send_buf, total))
		return -1;

	return bytes;
}

static uint32_t out_get_sample_rate(const struct audio_stream *stream)
{
	struct sco_stream_out *out = (struct sco_stream_out *) stream;

	DBG("rate %u", out->cfg.rate);

	return out->cfg.rate;
}

static int out_set_sample_rate(struct audio_stream *stream, uint32_t rate)
{
	DBG("rate %u", rate);

	return 0;
}

static size_t out_get_buffer_size(const struct audio_stream *stream)
{
	struct sco_stream_out *out = (struct sco_stream_out *) stream;
	size_t size = audio_stream_frame_size(&out->stream.common) *
							out->cfg.frame_num;

	DBG("buf size %zd", size);

	return size;
}

static uint32_t out_get_channels(const struct audio_stream *stream)
{
	struct sco_stream_out *out = (struct sco_stream_out *) stream;

	DBG("channels num: %u", popcount(out->cfg.channels));

	return out->cfg.channels;
}

static audio_format_t out_get_format(const struct audio_stream *stream)
{
	struct sco_stream_out *out = (struct sco_stream_out *) stream;

	DBG("format: %u", out->cfg.format);

	return out->cfg.format;
}

static int out_set_format(struct audio_stream *stream, audio_format_t format)
{
	DBG("");

	return -ENOSYS;
}

static int out_standby(struct audio_stream *stream)
{
	DBG("");

	return 0;
}

static int out_dump(const struct audio_stream *stream, int fd)
{
	DBG("");

	return -ENOSYS;
}

static int out_set_parameters(struct audio_stream *stream, const char *kvpairs)
{
	DBG("%s", kvpairs);

	return 0;
}

static char *out_get_parameters(const struct audio_stream *stream,
							const char *keys)
{
	DBG("");

	return strdup("");
}

static uint32_t out_get_latency(const struct audio_stream_out *stream)
{
	DBG("");

	return 0;
}

static int out_set_volume(struct audio_stream_out *stream, float left,
								float right)
{
	DBG("");

	return -ENOSYS;
}

static int out_get_render_position(const struct audio_stream_out *stream,
							uint32_t *dsp_frames)
{
	DBG("");

	return -ENOSYS;
}

static int out_add_audio_effect(const struct audio_stream *stream,
							effect_handle_t effect)
{
	DBG("");

	return -ENOSYS;
}

static int out_remove_audio_effect(const struct audio_stream *stream,
							effect_handle_t effect)
{
	DBG("");

	return -ENOSYS;
}

static int sco_open_output_stream(struct audio_hw_device *dev,
					audio_io_handle_t handle,
					audio_devices_t devices,
					audio_output_flags_t flags,
					struct audio_config *config,
					struct audio_stream_out **stream_out)
{
	struct sco_dev *adev = (struct sco_dev *) dev;
	struct sco_stream_out *out;
	int chan_num, ret;
	size_t resample_size;

	DBG("config %p device flags 0x%02x", config, devices);

	if (ipc_connect_sco() != SCO_STATUS_SUCCESS) {
		error("sco: cannot get fd");
		return -EIO;
	}

	DBG("got sco fd %d mtu %u", sco_fd, sco_mtu);

	out = calloc(1, sizeof(struct sco_stream_out));
	if (!out)
		return -ENOMEM;

	out->stream.common.get_sample_rate = out_get_sample_rate;
	out->stream.common.set_sample_rate = out_set_sample_rate;
	out->stream.common.get_buffer_size = out_get_buffer_size;
	out->stream.common.get_channels = out_get_channels;
	out->stream.common.get_format = out_get_format;
	out->stream.common.set_format = out_set_format;
	out->stream.common.standby = out_standby;
	out->stream.common.dump = out_dump;
	out->stream.common.set_parameters = out_set_parameters;
	out->stream.common.get_parameters = out_get_parameters;
	out->stream.common.add_audio_effect = out_add_audio_effect;
	out->stream.common.remove_audio_effect = out_remove_audio_effect;
	out->stream.get_latency = out_get_latency;
	out->stream.set_volume = out_set_volume;
	out->stream.write = out_write;
	out->stream.get_render_position = out_get_render_position;

	if (config) {
		DBG("config: rate %u chan mask %x format %d offload %p",
				config->sample_rate, config->channel_mask,
				config->format, &config->offload_info);

		out->cfg.format = config->format;
		out->cfg.channels = config->channel_mask;
		out->cfg.rate = config->sample_rate;
	} else {
		out->cfg.format = AUDIO_STREAM_DEFAULT_FORMAT;
		out->cfg.channels = AUDIO_CHANNEL_OUT_STEREO;
		out->cfg.rate = AUDIO_STREAM_DEFAULT_RATE;
	}

	out->cfg.frame_num = OUT_STREAM_FRAMES;

	out->downmix_buf = malloc(out_get_buffer_size(&out->stream.common));
	if (!out->downmix_buf) {
		free(out);
		return -ENOMEM;
	}

	out->cache = malloc(sco_mtu);
	if (!out->cache) {
		free(out->downmix_buf);
		free(out);
		return -ENOMEM;
	}

	DBG("size %zd", out_get_buffer_size(&out->stream.common));

	/* Channel numbers for resampler */
	chan_num = 1;

	ret = create_resampler(out->cfg.rate, AUDIO_STREAM_SCO_RATE, chan_num,
						RESAMPLER_QUALITY_DEFAULT, NULL,
						&out->resampler);
	if (ret) {
		error("Failed to create resampler (%s)", strerror(ret));
		goto failed;
	}

	DBG("Created resampler: input rate [%d] output rate [%d] channels [%d]",
				out->cfg.rate, AUDIO_STREAM_SCO_RATE, chan_num);

	out->resample_frame_num = get_resample_frame_num(AUDIO_STREAM_SCO_RATE,
							out->cfg.rate,
							out->cfg.frame_num, 1);

	if (!out->resample_frame_num) {
		error("frame num is too small to resample, discard it");
		goto failed;
	}

	resample_size = sizeof(int16_t) * chan_num * out->resample_frame_num;

	out->resample_buf = malloc(resample_size);
	if (!out->resample_buf) {
		error("failed to allocate resample buffer for %u frames",
						out->resample_frame_num);
		goto failed;
	}

	DBG("resampler: frame num %u buf size %zd bytes",
					out->resample_frame_num, resample_size);

	*stream_out = &out->stream;
	adev->out = out;

	return 0;
failed:
	if (out->resampler)
		release_resampler(out->resampler);

	free(out->cache);
	free(out->downmix_buf);
	free(out);
	stream_out = NULL;
	adev->out = NULL;

	return ret;
}

static void close_sco_socket(void)
{
	DBG("");

	pthread_mutex_lock(&sco_mutex);

	if (sco_fd >= 0) {
		shutdown(sco_fd, SHUT_RDWR);
		close(sco_fd);
		sco_fd = -1;
	}

	pthread_mutex_unlock(&sco_mutex);
}

static void sco_close_output_stream(struct audio_hw_device *dev,
					struct audio_stream_out *stream_out)
{
	struct sco_dev *sco_dev = (struct sco_dev *) dev;
	struct sco_stream_out *out = (struct sco_stream_out *) stream_out;

	DBG("dev %p stream %p fd %d", dev, out, sco_fd);

	close_sco_socket();

	if (out->resampler)
		release_resampler(out->resampler);

	free(out->cache);
	free(out->downmix_buf);
	free(out);
	sco_dev->out = NULL;
}

static int sco_set_parameters(struct audio_hw_device *dev,
							const char *kvpairs)
{
	DBG("%s", kvpairs);

	return 0;
}

static char *sco_get_parameters(const struct audio_hw_device *dev,
							const char *keys)
{
	DBG("");

	return strdup("");
}

static int sco_init_check(const struct audio_hw_device *dev)
{
	DBG("");

	return 0;
}

static int sco_set_voice_volume(struct audio_hw_device *dev, float volume)
{
	DBG("%f", volume);

	return 0;
}

static int sco_set_master_volume(struct audio_hw_device *dev, float volume)
{
	DBG("%f", volume);

	return 0;
}

static int sco_set_mode(struct audio_hw_device *dev, int mode)
{
	DBG("");

	return -ENOSYS;
}

static int sco_set_mic_mute(struct audio_hw_device *dev, bool state)
{
	DBG("");

	return -ENOSYS;
}

static int sco_get_mic_mute(const struct audio_hw_device *dev, bool *state)
{
	DBG("");

	return -ENOSYS;
}

static size_t sco_get_input_buffer_size(const struct audio_hw_device *dev,
					const struct audio_config *config)
{
	DBG("");

	return -ENOSYS;
}

static uint32_t in_get_sample_rate(const struct audio_stream *stream)
{
	struct sco_stream_in *in = (struct sco_stream_in *) stream;

	DBG("rate %u", in->cfg.rate);

	return in->cfg.rate;
}

static int in_set_sample_rate(struct audio_stream *stream, uint32_t rate)
{
	DBG("rate %u", rate);

	return 0;
}

static size_t in_get_buffer_size(const struct audio_stream *stream)
{
	struct sco_stream_in *in = (struct sco_stream_in *) stream;
	size_t size = audio_stream_frame_size(&in->stream.common) *
							in->cfg.frame_num;

	DBG("buf size %zd", size);

	return size;
}

static uint32_t in_get_channels(const struct audio_stream *stream)
{
	struct sco_stream_in *in = (struct sco_stream_in *) stream;

	DBG("channels num: %u", popcount(in->cfg.channels));

	return in->cfg.channels;
}

static audio_format_t in_get_format(const struct audio_stream *stream)
{
	struct sco_stream_in *in = (struct sco_stream_in *) stream;

	DBG("format: %u", in->cfg.format);

	return in->cfg.format;
}

static int in_set_format(struct audio_stream *stream, audio_format_t format)
{
	DBG("");

	return -ENOSYS;
}

static int in_standby(struct audio_stream *stream)
{
	DBG("");

	return 0;
}

static int in_dump(const struct audio_stream *stream, int fd)
{
	DBG("");

	return -ENOSYS;
}

static int in_set_parameters(struct audio_stream *stream, const char *kvpairs)
{
	DBG("%s", kvpairs);

	return 0;
}

static char *in_get_parameters(const struct audio_stream *stream,
							const char *keys)
{
	DBG("");

	return strdup("");
}

static int in_add_audio_effect(const struct audio_stream *stream,
							effect_handle_t effect)
{
	DBG("");

	return -ENOSYS;
}

static int in_remove_audio_effect(const struct audio_stream *stream,
							effect_handle_t effect)
{
	DBG("");

	return -ENOSYS;
}

static int in_set_gain(struct audio_stream_in *stream, float gain)
{
	DBG("");

	return -ENOSYS;
}

static ssize_t in_read(struct audio_stream_in *stream, void *buffer,
								size_t bytes)
{
	DBG("");

	return -ENOSYS;
}

static uint32_t in_get_input_frames_lost(struct audio_stream_in *stream)
{
	DBG("");

	return -ENOSYS;
}

static int sco_open_input_stream(struct audio_hw_device *dev,
					audio_io_handle_t handle,
					audio_devices_t devices,
					struct audio_config *config,
					struct audio_stream_in **stream_in)
{
	struct sco_dev *sco_dev = (struct sco_dev *) dev;
	struct sco_stream_in *in;

	DBG("");

	in = calloc(1, sizeof(struct sco_stream_in));
	if (!in)
		return -ENOMEM;

	in->stream.common.get_sample_rate = in_get_sample_rate;
	in->stream.common.set_sample_rate = in_set_sample_rate;
	in->stream.common.get_buffer_size = in_get_buffer_size;
	in->stream.common.get_channels = in_get_channels;
	in->stream.common.get_format = in_get_format;
	in->stream.common.set_format = in_set_format;
	in->stream.common.standby = in_standby;
	in->stream.common.dump = in_dump;
	in->stream.common.set_parameters = in_set_parameters;
	in->stream.common.get_parameters = in_get_parameters;
	in->stream.common.add_audio_effect = in_add_audio_effect;
	in->stream.common.remove_audio_effect = in_remove_audio_effect;
	in->stream.set_gain = in_set_gain;
	in->stream.read = in_read;
	in->stream.get_input_frames_lost = in_get_input_frames_lost;

	if (config) {
		DBG("config: rate %u chan mask %x format %d offload %p",
				config->sample_rate, config->channel_mask,
				config->format, &config->offload_info);

		in->cfg.format = config->format;
		in->cfg.channels = config->channel_mask;
		in->cfg.rate = config->sample_rate;
	} else {
		in->cfg.format = AUDIO_STREAM_DEFAULT_FORMAT;
		in->cfg.channels = AUDIO_CHANNEL_OUT_MONO;
		in->cfg.rate = AUDIO_STREAM_DEFAULT_RATE;
	}

	*stream_in = &in->stream;
	sco_dev->in = in;

	return 0;
}

static void sco_close_input_stream(struct audio_hw_device *dev,
					struct audio_stream_in *stream_in)
{
	struct sco_dev *sco_dev = (struct sco_dev *) dev;
	struct sco_stream_in *in = (struct sco_stream_in *) stream_in;

	DBG("dev %p stream %p fd %d", dev, in, sco_fd);

	close_sco_socket();

	free(in);
	sco_dev->in = NULL;
}

static int sco_dump(const audio_hw_device_t *device, int fd)
{
	DBG("");

	return 0;
}

static int sco_close(hw_device_t *device)
{
	DBG("");

	free(device);

	return 0;
}

static void *ipc_handler(void *data)
{
	bool done = false;
	struct pollfd pfd;
	int sk;

	DBG("");

	while (!done) {
		DBG("Waiting for connection ...");

		sk = accept(listen_sk, NULL, NULL);
		if (sk < 0) {
			int err = errno;

			if (err == EINTR)
				continue;

			if (err != ECONNABORTED && err != EINVAL)
				error("sco: Failed to accept socket: %d (%s)",
							err, strerror(err));

			break;
		}

		pthread_mutex_lock(&sk_mutex);
		ipc_sk = sk;
		pthread_mutex_unlock(&sk_mutex);

		DBG("SCO IPC: Connected");

		memset(&pfd, 0, sizeof(pfd));
		pfd.fd = ipc_sk;
		pfd.events = POLLHUP | POLLERR | POLLNVAL;

		/* Check if socket is still alive. Empty while loop.*/
		while (poll(&pfd, 1, -1) < 0 && errno == EINTR);

		if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) {
			info("SCO HAL: Socket closed");

			pthread_mutex_lock(&sk_mutex);
			close(ipc_sk);
			ipc_sk = -1;
			pthread_mutex_unlock(&sk_mutex);
		}
	}

	info("Closing SCO IPC thread");
	return NULL;
}

static int sco_ipc_init(void)
{
	struct sockaddr_un addr;
	int err;
	int sk;

	DBG("");

	sk = socket(PF_LOCAL, SOCK_SEQPACKET, 0);
	if (sk < 0) {
		err = -errno;
		error("sco: Failed to create socket: %d (%s)", -err,
								strerror(-err));
		return err;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	memcpy(addr.sun_path, BLUEZ_SCO_SK_PATH, sizeof(BLUEZ_SCO_SK_PATH));

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = -errno;
		error("sco: Failed to bind socket: %d (%s)", -err,
								strerror(-err));
		goto failed;
	}

	if (listen(sk, 1) < 0) {
		err = -errno;
		error("sco: Failed to listen on the socket: %d (%s)", -err,
								strerror(-err));
		goto failed;
	}

	listen_sk = sk;

	err = pthread_create(&ipc_th, NULL, ipc_handler, NULL);
	if (err) {
		err = -err;
		ipc_th = 0;
		error("sco: Failed to start IPC thread: %d (%s)",
							-err, strerror(-err));
		goto failed;
	}

	return 0;

failed:
	close(sk);
	return err;
}

static int sco_open(const hw_module_t *module, const char *name,
							hw_device_t **device)
{
	struct sco_dev *dev;
	int err;

	DBG("");

	if (strcmp(name, AUDIO_HARDWARE_INTERFACE)) {
		error("SCO: interface %s not matching [%s]", name,
						AUDIO_HARDWARE_INTERFACE);
		return -EINVAL;
	}

	err = sco_ipc_init();
	if (err < 0)
		return err;

	dev = calloc(1, sizeof(struct sco_dev));
	if (!dev)
		return -ENOMEM;

	dev->dev.common.tag = HARDWARE_DEVICE_TAG;
	dev->dev.common.version = AUDIO_DEVICE_API_VERSION_CURRENT;
	dev->dev.common.module = (struct hw_module_t *) module;
	dev->dev.common.close = sco_close;

	dev->dev.init_check = sco_init_check;
	dev->dev.set_voice_volume = sco_set_voice_volume;
	dev->dev.set_master_volume = sco_set_master_volume;
	dev->dev.set_mode = sco_set_mode;
	dev->dev.set_mic_mute = sco_set_mic_mute;
	dev->dev.get_mic_mute = sco_get_mic_mute;
	dev->dev.set_parameters = sco_set_parameters;
	dev->dev.get_parameters = sco_get_parameters;
	dev->dev.get_input_buffer_size = sco_get_input_buffer_size;
	dev->dev.open_output_stream = sco_open_output_stream;
	dev->dev.close_output_stream = sco_close_output_stream;
	dev->dev.open_input_stream = sco_open_input_stream;
	dev->dev.close_input_stream = sco_close_input_stream;
	dev->dev.dump = sco_dump;

	*device = &dev->dev.common;

	return 0;
}

static struct hw_module_methods_t hal_module_methods = {
	.open = sco_open,
};

struct audio_module HAL_MODULE_INFO_SYM = {
	.common = {
		.tag = HARDWARE_MODULE_TAG,
		.version_major = 1,
		.version_minor = 0,
		.id = AUDIO_HARDWARE_MODULE_ID,
		.name = "SCO Audio HW HAL",
		.author = "Intel Corporation",
		.methods = &hal_module_methods,
	},
};
