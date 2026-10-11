// Marque ILLWATCH (v7) : un œil dont l'iris est un balayage radar — la veille, littéralement.
// Couleurs en attributs SVG (pas de style en ligne) : compatible avec `style-src 'self'`.

export function Logo({ size = 32, title }: { size?: number; title?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      role={title ? "img" : undefined}
      aria-hidden={title ? undefined : true}
      aria-label={title}
      className="logo"
    >
      <path
        d="M2.5 16C6.4 9.2 11 6 16 6s9.6 3.2 13.5 10C25.6 22.8 21 26 16 26S6.4 22.8 2.5 16Z"
        fill="#161036"
        stroke="#8E80FF"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <circle cx="16" cy="16" r="6.2" fill="#2A1F78" stroke="#8E80FF" strokeWidth="1.3" />
      <path className="logo-sweep" d="M16 16V9.8a6.2 6.2 0 0 1 5.37 3.1Z" fill="#F27A2E" />
      <circle cx="16" cy="16" r="1.9" fill="#F27A2E" />
    </svg>
  );
}

/** Marque et nom : rail de navigation et écran de connexion. */
export function Lockup({ size = 32 }: { size?: number }) {
  return (
    <span className="lockup">
      <Logo size={size} />
      <span className="lockup-text">
        <strong>ILLWATCH</strong>
        <small>par CYBERILLSEC</small>
      </span>
    </span>
  );
}
