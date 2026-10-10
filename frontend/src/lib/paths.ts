// Règles d'adresse du routage interne (sans JSX : testées directement par Node).

/** Adresse interne valide : « /chemin », jamais « //hote », « /\hote » ni « https:… ». */
export function isInternalPath(to: string): boolean {
  return /^\/(?![/\\])[^\s\\]*$/.test(to);
}

/** Vrai si `to` désigne l'écran courant (ou un de ses sous-écrans, sauf pour « / »). */
export function isActive(pathname: string, to: string): boolean {
  if (to === "/") return pathname === "/";
  return pathname === to || pathname.startsWith(`${to}/`);
}
