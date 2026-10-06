import { Field } from '../components'
import { trafficModes, trafficUnits } from '../server-assets'
import type { AssetDraft, TrafficUnit } from '../server-assets'

export function SetupNavigation({ monitoring = false }: { monitoring?: boolean }) {
  const sections = [['setup-basics', '名称'], ['setup-labels', '地区标签'], ['setup-cost', '成本到期'], ['setup-traffic', '流量额度'], ['setup-operations', '告警下载'], ...(monitoring ? [['setup-monitoring', '监控'], ['setup-probes', '拨测']] : [])]
  return <nav className="server-setup-shortcuts ui-tab-list" aria-label="配置分区">{sections.map(([id, title]) => <button type="button" key={id} onClick={() => document.getElementById(id)?.closest('section')?.scrollIntoView({ block: 'start' })}>{title}</button>)}</nav>
}

export default function ServerAssetFields({ value, onChange }: { value: AssetDraft; onChange: (value: AssetDraft) => void }) {
  const update = (change: Partial<AssetDraft>) => onChange({ ...value, ...change })
  return <>
    <section className="server-setup-section" aria-labelledby="setup-labels">
      <div className="server-setup-heading"><div><h3 id="setup-labels">地区与标签</h3><p>在展示页标记位置、归类和筛选服务器。</p></div><span className="server-setup-tag">可选</span></div>
      <div className="server-setup-grid">
        <Field label="地区代码"><input maxLength={16} value={value.region} onChange={event => update({ region: event.target.value.toUpperCase() })} placeholder="例如：CN / JP / DE" /></Field>
        <Field label="展示分组"><input maxLength={40} value={value.group_name} onChange={event => update({ group_name: event.target.value })} placeholder="例如：主力 / 备用" /></Field>
      </div>
      <div className="server-asset-full"><Field label="标签" hint="用逗号分隔，最多 16 个，每个最多 32 字。"><input value={value.tags} maxLength={544} onChange={event => update({ tags: event.target.value })} placeholder="例如：主力, 线路:BGP" /></Field></div>
      <label className="server-setup-toggle"><span><strong>在展示页隐藏</strong><small>后台管理仍可查看和编辑。</small></span><input type="checkbox" role="switch" checked={value.hidden} onChange={event => update({ hidden: event.target.checked })} /><span className="server-setup-switch" aria-hidden="true" /></label>
    </section>
    <section className="server-setup-section" aria-labelledby="setup-cost">
      <div className="server-setup-heading"><div><h3 id="setup-cost">成本与到期</h3><p>记录服务器费用与下次到期日期。</p></div><span className="server-setup-tag">可选</span></div>
      <div className="server-setup-grid server-assets-three">
        <Field label="每周期金额" hint="留空表示未填写，0 表示免费。"><input type="number" min={0} max={1000000000} step="0.01" value={value.price} onChange={event => update({ price: event.target.value })} placeholder="未填写" /></Field>
        <Field label="币种"><input required pattern="[A-Za-z]{3}" maxLength={3} value={value.currency} onChange={event => update({ currency: event.target.value.toUpperCase() })} list="server-currencies" /><datalist id="server-currencies">{['CNY', 'USD', 'EUR', 'HKD', 'JPY', 'GBP', 'SGD'].map(code => <option key={code} value={code} />)}</datalist></Field>
        <Field label="费用周期（天）" hint="0 为一次性；可输入自定义天数。"><input required type="number" min={0} max={3650} value={value.billing_cycle} onChange={event => update({ billing_cycle: event.target.value, ...(Number(event.target.value) === 0 ? { auto_renewal: false } : {}) })} list="server-billing-cycles" /><datalist id="server-billing-cycles"><option value="30">30 天</option><option value="90">90 天</option><option value="180">180 天</option><option value="365">365 天</option><option value="0">一次性</option></datalist></Field>
      </div>
      <div className="server-asset-full"><Field label="到期日期（UTC）" hint="到期时间按所选日期的 UTC 零点记录。"><input type="date" min="1970-01-01" max="9999-12-31" value={value.expiry} onChange={event => update({ expiry: event.target.value, ...(!event.target.value ? { auto_renewal: false } : {}) })} /></Field></div>
      <label className="server-setup-toggle"><span><strong>自动顺延到期记录</strong><small>到期后按费用周期更新日期记录；不会向供应商付款。需先设置到期日期与非零周期。</small></span><input type="checkbox" role="switch" checked={value.auto_renewal} disabled={!value.expiry || Number(value.billing_cycle) <= 0} onChange={event => update({ auto_renewal: event.target.checked })} /><span className="server-setup-switch" aria-hidden="true" /></label>
    </section>
    <section className="server-setup-section" aria-labelledby="setup-traffic">
      <div className="server-setup-heading"><div><h3 id="setup-traffic">流量额度</h3><p>按账单日汇总网卡观测流量，展示本期使用与剩余额度。</p></div><span className="server-setup-tag">可选</span></div>
      <div className="server-setup-grid server-assets-three">
        <div><Field label="每期流量额度"><input required inputMode="decimal" pattern="[0-9]+(\.[0-9]{1,6})?" value={value.amount} onChange={event => update({ amount: event.target.value })} /></Field><select className="server-asset-unit" aria-label="流量额度单位" value={value.unit} onChange={event => update({ unit: event.target.value as TrafficUnit })}>{Object.keys(trafficUnits).map(unit => <option key={unit} value={unit}>{unit}</option>)}</select></div>
        <Field label="流量统计口径"><select value={value.traffic_limit_type} onChange={event => update({ traffic_limit_type: event.target.value as AssetDraft['traffic_limit_type'] })}>{Object.entries(trafficModes).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></Field>
        <Field label="每月重置日（UTC）" hint="1–31 日；短月按当月最后一天。"><input type="number" min={1} max={31} required value={value.reset_day} onChange={event => update({ reset_day: event.target.value })} /></Field>
      </div>
      <p className="server-setup-help">0 表示不设额度。GB / TB 为十进制，GiB / TiB 为二进制。超额仅标记状态。</p>
      <div className="server-asset-full"><Field label="统计网卡" hint="留空统计所有上报网卡；支持 * 匹配和 ! 排除，逗号分隔。建议指定出口网卡，避免虚拟与回环接口重复统计。"><input maxLength={1040} value={value.network_interface} onChange={event => update({ network_interface: event.target.value })} placeholder="例如：eth*,!eth1" /></Field></div>
      <p className="server-setup-help">从首个有效采样建立基线；接入前、重启或缺失期间的流量可能不完整，观测值可能与供应商账单不同。修改口径或网卡选择会按已有记录重新汇总。</p>
    </section>
  </>
}
