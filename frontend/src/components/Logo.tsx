// Marque ILL Watch (brand book v2, ADR-018). Le symbole reprend exactement la géométrie de
// docs/assets/illwatch-mark.svg : écu indigo, contour et radar Signal, point de menace orange.
// Couleurs en attributs SVG (aucun style en ligne) : compatible avec `style-src 'self'`.
// Le logotype n'est jamais recomposé avec une police : l'écran de connexion affiche le fichier
// vectorisé du kit (BrandLogo) ; le menu suit la spécification « nav-brand » du kit.
import { useId } from "react";

import { shell } from "../layout/shell.i18n";
import endorsedDark from "../assets/brand/illwatch-logo-endorsed-dark.svg";
import logoDark from "../assets/brand/illwatch-logo-dark.svg";

const SHIELD = "M50 5 L87 17.5 V47 C87 71.5 71.5 88.5 50 96 C28.5 88.5 13 71.5 13 47 V17.5 Z";
const SIGNAL = "#22D3EE";
const ORANGE = "#E6681B";

export function Logo({ size = 32, title }: { size?: number; title?: string }) {
  const id = useId().replace(/:/g, "");
  const clip = `iw-clip-${id}`;
  const sweep = `iw-sweep-${id}`;
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 100 100"
      role={title ? "img" : undefined}
      aria-hidden={title ? undefined : true}
      aria-label={title}
      className="logo"
    >
      <defs>
        <clipPath id={clip}>
          <path d={SHIELD} />
        </clipPath>
        <linearGradient id={sweep} x1="50" y1="58" x2="58.8" y2="25.2" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor={SIGNAL} stopOpacity="0.95" />
          <stop offset="1" stopColor={SIGNAL} stopOpacity="0.08" />
        </linearGradient>
      </defs>
      <path d={SHIELD} fill="#20155C" />
      <g clipPath={`url(#${clip})`}>
        <circle cx="50" cy="58" r="13" fill="none" stroke={SIGNAL} strokeWidth="1.6" strokeOpacity="0.55" />
        <circle cx="50" cy="58" r="26" fill="none" stroke={SIGNAL} strokeWidth="1.6" strokeOpacity="0.35" />
        <circle cx="50" cy="58" r="39" fill="none" stroke={SIGNAL} strokeWidth="1.6" strokeOpacity="0.2" />
        <path d="M50 58 L42.36 14.67 A44 44 0 0 1 83.71 29.72 Z" fill={`url(#${sweep})`} />
        <line x1="50" y1="58" x2="83.71" y2="29.72" stroke={SIGNAL} strokeWidth="2.4" strokeLinecap="round" />
      </g>
      <path d={SHIELD} fill="none" stroke={SIGNAL} strokeWidth="4.2" strokeLinejoin="round" />
      <circle cx="50" cy="58" r="3.6" fill={SIGNAL} />
      <circle cx="56.89" cy="33.97" r="4.6" fill={ORANGE} />
      <circle cx="56.89" cy="33.97" r="8.2" fill="none" stroke={ORANGE} strokeWidth="1.4" strokeOpacity="0.55" />
    </svg>
  );
}

/** Menu latéral : symbole 32 px, « ILL Watch » et l'endossement « PAR CYBERILL ». */
export function Lockup({ size = 32 }: { size?: number }) {
  return (
    <span className="lockup">
      <Logo size={size} />
      <span className="lockup-text">
        <strong>ILL Watch</strong>
        <small>{shell("endorsement")}</small>
      </span>
    </span>
  );
}

/** Logotype officiel (fichier vectorisé du kit), avec ou sans endossement, sur fond sombre. */
export function BrandLogo({ endorsed = true, className = "brand-logo" }: { endorsed?: boolean; className?: string }) {
  return (
    <img
      className={className}
      src={endorsed ? endorsedDark : logoDark}
      alt={shell("logoAlt")}
      width={endorsed ? 387 : 424}
      height={120}
    />
  );
}
