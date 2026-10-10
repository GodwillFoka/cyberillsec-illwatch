import { Link } from "react-router-dom";

/** Écran prévu au lot 1, pas encore livré : on le dit, sans contenu factice. */
export function Upcoming({ title, description }: { title: string; description: string }) {
  return (
    <>
      <div className="page-head">
        <div>
          <h1>{title}</h1>
          <p>{description}</p>
        </div>
      </div>
      <p className="notice">
        Écran en cours de développement (ADR-016, lot 1). Les données existent déjà dans l'API ;
        en attendant, la <Link to="/">vue d'ensemble</Link> en résume l'essentiel.
      </p>
    </>
  );
}

export function NotFound() {
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Page introuvable</h1>
          <p>Cette adresse ne correspond à aucun écran d'ILLWATCH.</p>
        </div>
      </div>
      <Link className="btn" to="/">
        Retour à la vue d'ensemble
      </Link>
    </>
  );
}
