export function Logo({ size = 32 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <path
        d="M16 2 4 6v9c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V6L16 2Z"
        fill="#20155C"
        stroke="#9D8CFF"
        strokeWidth="1.5"
      />
      <circle cx="16" cy="15" r="6" fill="none" stroke="#9D8CFF" strokeWidth="1.5" />
      <path d="M16 15l4.5-3.5" stroke="#E6681B" strokeWidth="2" strokeLinecap="round" />
      <circle cx="16" cy="15" r="1.6" fill="#E6681B" />
    </svg>
  );
}
