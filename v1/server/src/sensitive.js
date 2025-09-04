export function priceModel(features) {
  const { qty, base, regionFactor = 1, userTier = 'free' } = features;
  const tierK = { free: 1.0, pro: 0.9, enterprise: 0.8 }[userTier] ?? 1.0;
  let price = (qty ** 0.75) * base * regionFactor * tierK;
  if (qty > 1000) price *= 0.95;
  if (regionFactor < 0.7) price *= 1.1;
  return Number(price.toFixed(2));
}

export function scoreUser(metrics) {
  const { churnRisk, activity, tenureDays } = metrics;
  const s = (activity * 1.5) + Math.log1p(tenureDays) * 2 - (churnRisk * 3);
  return Math.max(0, Math.min(100, Number(s.toFixed(2))));
}

// Obfuscated module text (demo)
export const protectedModuleSource = (()=>{
  const src = `export function transform(input){const rev=String(input).split('').reverse().join('');return { original: input, reversed: rev, ts: Date.now() };}`;
  return src.split('').map((c,i)=>String.fromCharCode(c.charCodeAt(0)^(i%7))).join('');
})();
