import { Link } from "../lib/router";

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
