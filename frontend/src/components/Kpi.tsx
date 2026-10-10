import type { ReactNode } from "react";

interface Props {
  label: string;
  value: ReactNode;
  unit?: ReactNode;
  context?: ReactNode;
  alert?: boolean;
}

/** Carte indicateur : libellé, valeur dominante, contexte en une ligne. */
export function Kpi({ label, value, unit, context, alert }: Props) {
  return (
    <section className="card kpi">
      <div className="label">{label}</div>
      <div className="value">
        {value}
        {unit ? <small>{unit}</small> : null}
      </div>
      {context ? <div className={`context${alert ? " alert" : ""}`}>{context}</div> : null}
    </section>
  );
}
