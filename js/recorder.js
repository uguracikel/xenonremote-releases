import { timestampName } from './features.js';

const TYPES = ['video/webm;codecs=vp9,opus', 'video/webm;codecs=vp8,opus', 'video/webm'];

/** The first recording format this engine supports ('' = its default). */
export function recordingType(isSupported = (t) => window.MediaRecorder?.isTypeSupported?.(t)) {
  return TYPES.find((t) => isSupported(t)) || '';
}

/**
 * Records the remote screen (with its sound and voice chat) to a WebM file in
 * Downloads/Xenon Remote. Data is written while recording, so a long session
 * does not fill the memory.
 */
export class SessionRecorder {
  constructor(bridge) {
    this.bridge = bridge;
    this.recorder = null;
    this.startedAt = 0;
  }

  get active() {
    return Boolean(this.recorder);
  }

  async start(videoStream, audioStreams = [], prefix = 'Xenon-kayit') {
    if (this.recorder) return;
    const tracks = [...videoStream.getVideoTracks()];
    // MediaRecorder keeps only one audio track: mix all sounds into one.
    const sources = audioStreams.filter((s) => s && s.getAudioTracks().length);
    if (sources.length) {
      this.audio = new AudioContext();
      const dest = this.audio.createMediaStreamDestination();
      for (const s of sources) this.audio.createMediaStreamSource(s).connect(dest);
      tracks.push(dest.stream.getAudioTracks()[0]);
    }
    const mimeType = recordingType();
    const recorder = new MediaRecorder(new MediaStream(tracks), mimeType ? { mimeType, videoBitsPerSecond: 4_000_000 } : {});
    this.name = timestampName(prefix, 'webm');
    this.token = await this.bridge.fileBegin(this.name, -1);
    this.writes = Promise.resolve();
    this.failed = false;
    recorder.ondataavailable = (e) => {
      if (!e.data?.size) return;
      this.writes = this.writes
        .then(async () => this.bridge.fileWrite(this.token, new Uint8Array(await e.data.arrayBuffer())))
        .catch(() => { this.failed = true; });
    };
    this.stopped = new Promise((resolve) => { recorder.onstop = resolve; });
    recorder.start(1000);
    this.recorder = recorder;
    this.startedAt = Date.now();
  }

  /** Finishes the file; returns its saved path (or null). */
  async stop() {
    const recorder = this.recorder;
    if (!recorder) return null;
    this.recorder = null;
    if (recorder.state !== 'inactive') recorder.stop();
    await this.stopped;
    await this.writes;
    this.audio?.close().catch(() => {});
    this.audio = null;
    return this.bridge.fileEnd(this.token, !this.failed).catch(() => null);
  }
}
