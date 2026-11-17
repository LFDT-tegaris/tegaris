export interface SourceSimulationInput {
  readonly indexerProfileId: string;
  readonly projectionPlanId: string;
  readonly dataClass: string;
  readonly rangeStart: string;
  readonly rangeEnd: string;
  readonly maximumResponseBytes: string;
}

export const emptySourceSimulation: SourceSimulationInput = {
  indexerProfileId: '',
  projectionPlanId: '',
  dataClass: 'STATE_CALL',
  rangeStart: '',
  rangeEnd: '',
  maximumResponseBytes: '',
};

export function PolicySourceSimulation({
  value,
  onChange,
}: Readonly<{
  value: SourceSimulationInput;
  onChange: (next: SourceSimulationInput) => void;
}>) {
  return (
    <>
      {(
        [
          ['indexerProfileId', 'Indexer profile ID'],
          ['projectionPlanId', 'Projection plan ID'],
          ['rangeStart', 'First block'],
          ['rangeEnd', 'Last block'],
          ['maximumResponseBytes', 'Maximum response bytes'],
        ] as const
      ).map(([key, label]) => (
        <div key={key} className="grid gap-1 font-medium">
          <label htmlFor={`source-${key}`}>{label}</label>
          <input
            id={`source-${key}`}
            required
            value={value[key]}
            className="min-w-0 rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2 font-mono"
            inputMode={key.endsWith('Id') ? 'text' : 'numeric'}
            pattern={
              key.endsWith('Id')
                ? '[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}'
                : '[1-9][0-9]{0,19}'
            }
            onChange={(event) => onChange({ ...value, [key]: event.target.value })}
          />
        </div>
      ))}
      <div className="grid gap-1 font-medium">
        <label htmlFor="source-data-class">Source data class</label>
        <select
          id="source-data-class"
          value={value.dataClass}
          className="min-w-0 rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2"
          onChange={(event) => onChange({ ...value, dataClass: event.target.value })}
        >
          <option value="STATE_CALL">State call</option>
          <option value="EVENT_LOG">Event log</option>
          <option value="RECEIPT">Receipt</option>
          <option value="BLOCK_HEADER">Block header</option>
          <option value="FULL_BLOCK_TRANSACTIONS">Full block transactions</option>
        </select>
      </div>
    </>
  );
}
