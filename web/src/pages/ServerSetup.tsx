import { useFormDraft } from '../control-center/preferences'
import { useRef, useState } from 'react'
import { api } from '../api'
import { ErrorNotice, Field, Icon, Modal } from '../components'
import { useAction } from '../hooks'
import { emptyMonitoring, withMonitoring, initialProbePayloads } from '../probes'
import type { Probe, ProbeMonitoring } from '../probes'
import ProbeMonitoringFields from './ProbeMonitoringFields'
import type { AgentSettings, Server } from '../types'
import './server-setup.css'
import ServerOperationsFields from './ServerOperationsFields'
import { assetDraft, assetPayload } from '../server-assets'
import ServerAssetFields, { SetupNavigation } from './ServerAssetFields'

type ProbeDraft = Omit<Probe, 'id' | 'enabled' | 'port' | 'interval_secs'> & { key: number; port: string; interval: string; monitoring: ProbeMonitoring }
const frequencies = [
  { label: '实时', sample: '1', upload: '3', note: '及时观察变化' },
  { label: '均衡', sample: '3', upload: '10', note: '兼顾频率与开销' },
  { label: '轻量', sample: '10', upload: '30', note: '减少采集与请求' },
]

export function SetupSteps({ step }: { step: 1 | 2 }) {
  return <ol className="server-setup-steps" aria-label="添加服务器进度">
    <li className={step === 1 ? 'is-current' : 'is-complete'} aria-current={step === 1 ? 'step' : undefined}><span>{step === 2 ? <Icon name="check" size={15} /> : '1'}</span><div><strong>配置服务器</strong><small>名称、监控与拨测</small></div></li>
    <li className={step === 2 ? 'is-current' : ''} aria-current={step === 2 ? 'step' : undefined}><span>2</span><div><strong>安装与接入</strong><small>复制命令，等待上线</small></div></li>
  </ol>
}

export default function ServerSetup({ onClose, onCreated }: { onClose: () => void; onCreated: (server: Server) => void }) {
  const action = useAction()
  const [name, setName] = useState('')
  const [asset, setAsset] = useState(() => assetDraft())
  const [sample, setSample] = useState('1'), [upload, setUpload] = useState('3')
  const [persist, setPersist] = useState('60')
  const [autoUpdate, setAutoUpdate] = useState(false), [discover, setDiscover] = useState(true)
  const [probes, setProbes] = useState<ProbeDraft[]>([])
  const draft = useFormDraft<{ name: string; sample: string; upload: string; persist: string; autoUpdate: boolean; discover: boolean }>('server-setup', Boolean(name || probes.length))
  const nextKey = useRef(0)
  const updateProbe = (key: number, change: Partial<ProbeDraft>) => setProbes(current => current.map(probe => {
    if (probe.key !== key) return probe
    const changed = { ...probe, ...change }
    const identityChanged = changed.target !== probe.target || changed.kind !== probe.kind || changed.port !== probe.port || changed.monitoring.ip_version !== probe.monitoring.ip_version
    return identityChanged ? { ...changed, monitoring: { ...changed.monitoring, authorization: { ...changed.monitoring.authorization, confirmed: false } } } : changed
  }))
  const addProbe = () => {
    const key = nextKey.current++
    setProbes(current => current.length >= 32 ? current : [...current, { key, name: '', kind: 'tcp', target: '', port: '443', interval: '30', carrier: '', monitoring: emptyMonitoring() }])
  }
  const submit = () => {
    const agent_settings: AgentSettings = { sample_interval_secs: Number(sample), upload_interval_secs: Number(upload), auto_update: autoUpdate, discover_public_ips: discover }
    const initialProbes: Probe[] = probes.map(probe => withMonitoring({ id: '00000000-0000-0000-0000-000000000000', name: probe.name.trim(), kind: probe.kind, target: probe.target.trim(), port: probe.kind === 'tcp' ? Number(probe.port) : null, interval_secs: Number(probe.interval), carrier: probe.carrier.trim(), enabled: true, monitor: null }, probe.monitoring))
    void action.run(() => api<Server>('/api/servers', 'POST', { name: name.trim(), agent_settings, telemetry_settings: { persist_interval_secs: Number(persist) }, probes: initialProbePayloads(initialProbes), asset_settings: assetPayload(asset) }), onCreated)
  }

  return <Modal title="添加服务器" onClose={onClose} busy={action.busy} className="server-setup-modal">
    <form onSubmit={event => { event.preventDefault(); submit() }}>
      <SetupNavigation monitoring />
      <div className="server-setup-body">
        <SetupSteps step={1} />
        <ErrorNotice message={draft.error} retry={draft.reload} />
        <div className="control-actions"><button className="ui-button" type="button" disabled={!draft.ready || action.busy} onClick={() => void action.run(() => draft.save({ name, sample, upload, persist, autoUpdate, discover }))}>保存基础信息草稿</button><button className="ui-button" type="button" disabled={!draft.ready || !draft.value || action.busy} onClick={() => { const value = draft.value; if (value) { setName(value.name); setSample(value.sample); setUpload(value.upload); setPersist(value.persist); setAutoUpdate(value.autoUpdate); setDiscover(value.discover) } }}>恢复草稿</button><small>资产、拨测与凭据保持当前表单，草稿只保存基础信息和采集设置。</small></div>
        <div className="server-setup-intro"><span className="server-setup-mark"><Icon name="server" size={25} /></span><div><h3>连接一台新的服务器</h3><p>先设定监控方式，设备接入后自动同步。之后也可以在详情中调整。</p></div></div>
        <fieldset disabled={action.busy}>
          <section className="server-setup-section" aria-labelledby="setup-basics">
            <div className="server-setup-heading"><div><h3 id="setup-basics">基础信息</h3><p>一个容易辨认的名称，就是接入的开始。</p></div><span className="server-setup-tag">必填</span></div>
            <Field label="服务器名称" hint="系统、架构和硬件信息会在 Agent 接入后自动获取。"><input name="name" required pattern=".*\S.*" maxLength={128} value={name} onChange={event => setName(event.target.value)} placeholder="例如：东京 · 主节点" autoComplete="off" /></Field>
          </section>
          <ServerAssetFields value={asset} onChange={setAsset} />
      <ServerOperationsFields asset={asset} onChange={setAsset} />
          <section className="server-setup-section" aria-labelledby="setup-monitoring">
            <div className="server-setup-heading"><div><h3 id="setup-monitoring">监控与采集</h3><p>采样、实时上报和历史写入分别设置，兼顾展示速度与数据库开销。</p></div><Icon name="activity" size={20} /></div>
            <div className="server-setup-presets" role="group" aria-label="监控频率预设">{frequencies.map(frequency => <button key={frequency.label} type="button" aria-pressed={sample === frequency.sample && upload === frequency.upload} onClick={() => { setSample(frequency.sample); setUpload(frequency.upload) }}><strong>{frequency.label}</strong><span>{frequency.sample} 秒采样 · {frequency.upload} 秒上传</span><small>{frequency.note}</small></button>)}</div>
            <div className="server-setup-grid">
              <Field label="采样间隔（秒）" hint="每次采集系统指标的间隔，1–60 秒。"><input name="sample_interval_secs" type="number" min={1} max={60} step={1} required value={sample} onChange={event => setSample(event.target.value)} /></Field>
              <Field label="实时上报间隔（秒）" hint="应大于或等于采样间隔，最多 60 秒；不决定历史保存粒度。"><input name="upload_interval_secs" type="number" min={Number(sample) || 1} max={60} step={1} required value={upload} onChange={event => setUpload(event.target.value)} /></Field>
              <Field label="历史批量写入间隔（秒）" hint="15–3600 秒，默认 60 秒。新版 Agent 收到持久化确认后再清除本地缓存；旧 Agent 继续按原上传间隔写入。"><input name="persist_interval_secs" type="number" min={15} max={3600} step={1} required value={persist} onChange={event => setPersist(event.target.value)} /></Field>
            </div>
            <div className="server-setup-toggles">
              <label className="server-setup-toggle"><span><strong>自动识别公网地址</strong><small>识别 IPv4 / IPv6；设备本地关闭时，以本地设置为准。</small></span><input type="checkbox" role="switch" name="discover_public_ips" checked={discover} onChange={event => setDiscover(event.target.checked)} /><span className="server-setup-switch" aria-hidden="true" /></label>
              <label className="server-setup-toggle"><span><strong>自动更新 Agent</strong><small>从 GitHub 下载面板选定的兼容签名版本，保留设备身份与本地状态。</small></span><input type="checkbox" role="switch" name="auto_update" checked={autoUpdate} onChange={event => setAutoUpdate(event.target.checked)} /><span className="server-setup-switch" aria-hidden="true" /></label>
            </div>
          </section>
          <section className="server-setup-section" aria-labelledby="setup-probes">
            <div className="server-setup-heading"><div><h3 id="setup-probes">初始网络拨测 <span className="server-setup-tag">可选</span></h3><p>接入后持续检测指定目标，结果显示在服务器展示页。统一延迟任务中的默认目标也会自动分配。</p></div><button type="button" className="button button-secondary button-small" onClick={addProbe} disabled={probes.length >= 32}><Icon name="plus" size={15} />添加目标</button></div>
            {!probes.length && <div className="server-setup-probe-empty"><Icon name="nodes" size={23} /><div><strong>关心的线路，从接入时开始观察</strong><p>添加 TCP 目标查看延迟与连接失败率，或通过 ICMP 检测延迟与丢包。也可以稍后配置。</p></div></div>}
            {probes.map((probe, index) => <div key={probe.key} className="server-setup-probe" role="group" aria-label={`拨测目标 ${index + 1}`}>
              <div className="server-setup-probe-heading"><strong>目标 {String(index + 1).padStart(2, '0')}</strong><button type="button" className="text-button danger-text" onClick={() => setProbes(current => current.filter(item => item.key !== probe.key))} aria-label={`移除目标 ${index + 1}`}>移除</button></div>
              <div className="server-setup-grid server-setup-probe-grid">
                <Field label="拨测名称"><input required pattern=".*\S.*" maxLength={128} value={probe.name} onChange={event => updateProbe(probe.key, { name: event.target.value })} placeholder="例如：主站连通性" /></Field>
                <Field label="检测方式"><select value={probe.kind} onChange={event => updateProbe(probe.key, { kind: event.target.value as Probe['kind'] })}><option value="tcp">TCP 连接</option><option value="icmp">ICMP 回显</option></select></Field>
                <Field label="线路备注"><input maxLength={64} value={probe.carrier} onChange={event => updateProbe(probe.key, { carrier: event.target.value })} placeholder="例如：电信 / 联通 / 移动" /></Field>
                <Field label="目标地址"><input required maxLength={253} value={probe.target} onChange={event => updateProbe(probe.key, { target: event.target.value })} placeholder="主机名或 IP，不含协议和路径" autoCapitalize="none" spellCheck={false} /></Field>
                {probe.kind === 'tcp' && <Field label="目标端口"><input type="number" min={1} max={65535} step={1} required value={probe.port} onChange={event => updateProbe(probe.key, { port: event.target.value })} /></Field>}
                <Field label="拨测间隔（秒）"><input type="number" min={10} max={3600} step={1} required value={probe.interval} onChange={event => updateProbe(probe.key, { interval: event.target.value })} /></Field>
              </div>
              <ProbeMonitoringFields value={probe.monitoring} onChange={monitoring => updateProbe(probe.key, { monitoring })} />
              <p className="server-setup-help">{probe.kind === 'icmp' ? '设备需具备 ICMP 检测权限；工具或权限不可用时会显示检测错误。' : 'TCP 通过建立连接测量可达性，连接失败率与 ICMP 丢包率分别展示。'}</p>
            </div>)}
            {probes.length > 0 && <p className="server-setup-help">已配置 {probes.length} / 32 个目标。已确认目标授权且新版 Agent 取得最长 90 秒执行许可后才开始调度。断连和冷启动不沿用许可，可在服务器详情中编辑、撤销授权或暂停。</p>}
          </section>
        </fieldset>
        <ErrorNotice message={action.error} />
      </div>
      <footer className="server-setup-footer"><span>下一步：获取安装命令</span><button type="button" className="button button-secondary" disabled={action.busy} onClick={onClose}>取消</button><button type="submit" className="button button-primary" disabled={action.busy}>{action.busy ? <><span className="spinner" />正在创建…</> : <>创建并继续<Icon name="arrow" size={16} /></>}</button></footer>
    </form>
  </Modal>
}
