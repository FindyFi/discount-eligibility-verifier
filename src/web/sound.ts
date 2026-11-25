/**
 * Short synthesized feedback tones (no audio files). Browsers only allow audio after a user
 * gesture, so call unlock() from a click handler before results arrive.
 */
export class Sound {
  private ctx?: AudioContext;

  unlock(): void {
    try {
      const Ctor = window.AudioContext ?? (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
      if (!Ctor) return;
      this.ctx ??= new Ctor();
      if (this.ctx.state === 'suspended') void this.ctx.resume();
    } catch {
      /* audio unavailable */
    }
  }

  get ready(): boolean {
    return this.ctx?.state === 'running';
  }

  /** Two rising notes. */
  success(): void {
    this.tones([
      [660, 0, 0.12],
      [990, 0.13, 0.22],
    ], 'sine');
  }

  /** Two low buzzes. */
  failure(): void {
    this.tones([
      [220, 0, 0.18],
      [180, 0.22, 0.3],
    ], 'square', 0.12);
  }

  /** A single neutral note. */
  notice(): void {
    this.tones([[440, 0, 0.15]], 'triangle');
  }

  private tones(notes: [freq: number, start: number, duration: number][], type: OscillatorType, volume = 0.25): void {
    const ctx = this.ctx;
    if (!ctx || ctx.state !== 'running') return;
    const t0 = ctx.currentTime;
    for (const [freq, start, duration] of notes) {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = type;
      osc.frequency.value = freq;
      gain.gain.setValueAtTime(0, t0 + start);
      gain.gain.linearRampToValueAtTime(volume, t0 + start + 0.01);
      gain.gain.exponentialRampToValueAtTime(0.001, t0 + start + duration);
      osc.connect(gain).connect(ctx.destination);
      osc.start(t0 + start);
      osc.stop(t0 + start + duration + 0.02);
    }
  }
}
