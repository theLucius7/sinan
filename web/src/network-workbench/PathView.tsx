type Hop = { hop?: number; ip?: string | null; responders?: string[]; asn?: unknown; reverse_dns?: unknown; geolocation?: { latitude: number; longitude: number; source?: string; is_estimate?: boolean } | null; metadata_source?: string }
export default function PathView({ data }: { data: unknown }) {
 if (!data || typeof data !== 'object') return null
 const value = data as { hops?: Hop[]; external_as_path?: unknown }
 if (!Array.isArray(value.hops) || !value.hops.length) return null
 const locations = value.hops.map((hop, index) => ({ hop, index, location: hop.geolocation })).filter(item => item.location && Number.isFinite(item.location.latitude) && Number.isFinite(item.location.longitude))
 const x = (longitude: number) => (longitude + 180) * 2
 const y = (latitude: number) => (90 - latitude) * 2
 return <div className="nw-path"><h4>实际采集路径</h4><ol aria-label="逐跳线性拓扑">{value.hops.map((hop, index) => <li key={index}><strong>第{hop.hop ?? index + 1}跳</strong> {hop.responders?.join(' / ') || hop.ip || '未知 / 未响应'}{hop.asn != null && <span> · ASN {String(hop.asn)}</span>}{hop.reverse_dns != null && <span> · {String(hop.reverse_dns)}</span>}<small>资料来源：{hop.metadata_source || '未知'}</small></li>)}</ol>
 {locations.length > 0 ? <><p>地理辅助图：位置来自各跳资料源的估计，不代表确定机房或实际线路。</p><svg viewBox="0 0 720 360" role="img" aria-label="带来源的逐跳地理估计图"><rect x="0" y="0" width="720" height="360" fill="none" stroke="currentColor" /><path d="M0 180H720 M360 0V360" stroke="currentColor" opacity=".25" />{locations.map(({ index, location }, i) => { if (!location) return null; const previous = locations[i - 1]?.location; return <g key={index}>{previous && <line x1={x(previous.longitude)} y1={y(previous.latitude)} x2={x(location.longitude)} y2={y(location.latitude)} stroke="currentColor" strokeDasharray="4 4" />}<circle cx={x(location.longitude)} cy={y(location.latitude)} r="4" fill="currentColor" /><text x={x(location.longitude) + 6} y={y(location.latitude) - 6} fill="currentColor" fontSize="12">{index + 1}</text><title>第{index + 1}跳 · 来源 {location.source || '未知'} · 地理估计</title></g> })}</svg></> : <p>本报告缺少带来源的地理坐标，地图不可用。</p>}
 <p>外部 BGP / AS 路径资料：{value.external_as_path == null ? '未接入；不能从实际路由推断完整AS路径。' : '独立来源，详见结构化资料。'}</p></div>
}
