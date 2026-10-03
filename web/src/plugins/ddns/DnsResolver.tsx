import { useEffect, useState } from 'react'
import { api } from '../../api'
import { Badge, ErrorNotice, Field } from '../../components'
import { useAction, useResource } from '../../hooks'
import type { DnsAccount } from './DnsAccounts'

type Result = { status: string; rcode?: number; answers?: { name: string; kind: string; value: string; ttl: number }[]; error_code?: string | null; expected_match: boolean | null; resolver: string; transport?: string; elapsed_ms: number; checked_at: number; source: string }
type Observation = { id: string; request: { name: string; kind: string; expected: string[] }; result: Result }

export default function DnsResolver({ account, zoneId, initialName }: { account: DnsAccount; zoneId: string; initialName: string }) {
  const action = useAction()
  const [name, setName] = useState(initialName)
  const [kind, setKind] = useState('A')
  const [resolver, setResolver] = useState(''), [port, setPort] = useState(53), [expected, setExpected] = useState('')
  const history = useResource<Observation[]>(`/api/plugins/ddns/accounts/${account.id}/observations`)
  const [result, setResult] = useState<Result | null>(null)
  useEffect(() => { setName(initialName) }, [initialName])
  return <section className="panel-body"><h3>指定解析器传播观测</h3><p className="helper">从面板向明确选择的解析器发起有效 DNS 请求，分别保存名称、类型、解析器、记录值、TTL、响应码与耗时。UDP 响应截断时改用 TCP；提供方接受更新与解析器观察到的值分别表示。一次匹配不代表各地缓存长期一致。</p><ErrorNotice message={action.error || history.error} />
    <form onSubmit={event => { event.preventDefault(); void action.run(async () => {
      setResult(await api(`/api/plugins/ddns/accounts/${account.id}/resolve`, 'POST', { zone_id: zoneId, name, kind, resolver_ip: resolver, resolver_port: port, expected: expected ? expected.split('\n').filter(value => value !== '') : [] })); history.reload()
    }) }}><div className="form-grid"><Field label="查询名称"><input required value={name} onChange={event => setName(event.target.value)} placeholder="node.example.com" /></Field><Field label="记录类型"><select value={kind} onChange={event => setKind(event.target.value)}>{['A','AAAA','CNAME','TXT','MX','NS','SRV','CAA','HTTPS','SVCB'].map(kind => <option key={kind}>{kind}</option>)}</select></Field><Field label="解析器 IP" hint="明确填写 IPv4 或 IPv6；可使用已获授权的内网解析器。"><input required value={resolver} onChange={event => setResolver(event.target.value.trim())} placeholder="解析器的 IP 地址" /></Field><Field label="DNS 端口"><input type="number" required min={1} max={65535} value={port} onChange={event => setPort(Number(event.target.value))} /></Field><Field label="预期值（可选，每行一个）" hint="按完整值集合比较；MX 为优先级与主机名，SRV 为优先级、权重、端口与主机名。结构化类型暂显示原始十六进制。"><textarea rows={3} value={expected} onChange={event => setExpected(event.target.value)} /></Field></div><button className="button button-secondary" disabled={action.busy}>{action.busy ? '正在实际查询…' : '查询选定解析器'}</button></form>
    {result && <div className="panel-body"><Badge tone={result.status === 'error' || result.expected_match === false ? 'warm' : 'neutral'}>{result.status === 'error' ? '采集失败，结果未知' : result.expected_match === true ? '当前结果符合预期' : result.expected_match === false ? '当前结果与预期不同' : result.status === 'nxdomain' ? '解析器返回名称不存在' : result.status === 'no_data' ? '解析器未返回此类型记录' : result.status === 'resolver_error' ? '解析器返回错误响应' : '已采集解析器结果'}</Badge><p className="helper">从 {result.source} 到 {result.resolver} · {result.transport ?? '未完成'} · {result.elapsed_ms.toFixed(2)} 毫秒 · 响应码 {result.rcode ?? '未知'} · {new Date(result.checked_at * 1000).toLocaleString('zh-CN')}</p><pre>{JSON.stringify(result.answers ?? [], null, 2)}</pre></div>}
    <h4>不同解析器与历史结果</h4>{history.data?.slice(0, 12).map(entry => <article className="ddns-rule" key={entry.id}><strong>{entry.request.name} · {entry.request.kind} · {entry.result.resolver}</strong><p className="helper">{new Date(entry.result.checked_at * 1000).toLocaleString('zh-CN')} · {entry.result.status === 'error' ? '采集失败，结果未知' : `响应码 ${entry.result.rcode ?? '未知'}`} · {entry.result.elapsed_ms.toFixed(2)} 毫秒</p><pre>{JSON.stringify(entry.result.answers ?? [], null, 2)}</pre></article>)}
  </section>
}
