/**
 * Measure real throughput. Run with `bun run benchmark`.
 *
 * Numbers are machine-specific, so the host is recorded alongside them and
 * they are never asserted in CI. Inputs are generated rather than checked in so
 * the sizes are explicit.
 */
import { cpus, totalmem } from 'node:os';
import { find } from '../src/extract';

const CASES: ReadonlyArray<{ label: string; format: string; build: () => string }> = [
	{
		label: 'Access log',
		format: 'log',
		build: () =>
			Array.from(
				{ length: 40_000 },
				(_, i) =>
					`2026-08-12T10:${String(i % 60).padStart(2, '0')}:00Z level=info peer=10.${i % 256}.${(i >> 8) % 256}.7 upstream=[2001:db8::${(i % 65536).toString(16)}]:8080 dur=${i % 900}ms`,
			).join('\n'),
	},
	{
		label: 'JSON config',
		format: 'json',
		build: () =>
			JSON.stringify(
				Array.from({ length: 20_000 }, (_, i) => ({ host: `192.168.${i % 256}.${(i * 7) % 256}`, allow: '10.0.0.0/8', mac: 'aa:bb:cc:dd:ee:ff', note: `node ${i}` })),
				null,
				2,
			),
	},
	{
		label: 'Prose with no addresses',
		format: 'unknown',
		build: () => Array.from({ length: 40_000 }, (_, i) => `Release 2.${i % 10}.${i % 7} shipped at 10:30:00 on 2026-08-12 with build ${i}.`).join('\n'),
	},
];

const WARMUP = 2;
const RUNS = 7;
const median = (xs: readonly number[]) => {
	const s = [...xs].sort((a, b) => a - b);
	const mid = Math.floor(s.length / 2);
	return s.length % 2 ? (s[mid] as number) : ((s[mid - 1] as number) + (s[mid] as number)) / 2;
};

const results: Array<Record<string, unknown>> = [];
for (const c of CASES) {
	const content = c.build();
	const bytes = Buffer.byteLength(content, 'utf8');
	const run = () => find(content, c.format).length;
	for (let i = 0; i < WARMUP; i++) run();
	const durations: number[] = [];
	let count = 0;
	for (let i = 0; i < RUNS; i++) {
		const t0 = performance.now();
		count = run();
		durations.push(performance.now() - t0);
	}
	const ms = median(durations);
	results.push({
		label: c.label,
		bytes,
		lines: content.split('\n').length,
		extracted: count,
		ms: Number(ms.toFixed(2)),
		perSecond: count > 0 ? Math.round(count / (ms / 1000)) : null,
		mbPerSecond: Number((bytes / 1_048_576 / (ms / 1000)).toFixed(1)),
	});
	console.log(`${c.label.padEnd(18)} ${(bytes / 1_048_576).toFixed(2)} MB  ${String(count).padStart(7)}  ${ms.toFixed(2)} ms`);
}
const cpu = cpus()[0]?.model ?? 'unknown CPU';
await Bun.write(
	'benchmark-results.json',
	`${JSON.stringify({ host: `${cpu}, ${Math.round(totalmem() / 1_073_741_824)} GB RAM, Node ${process.versions.node}`, runs: RUNS, results }, null, 2)}\n`,
);
console.log('\nwrote benchmark-results.json');
