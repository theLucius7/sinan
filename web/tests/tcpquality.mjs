
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { resolve, extname, sep } from 'node:path'

// Use the committed bundle with loopback-only API fixtures.
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE
  ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url))
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' }
const server = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(root, path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': mime[extname(file)] ?? 'application/octet-stream' }); response.end(body) }
  catch { response.writeHead(404).end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const origin = `http://127.0.0.1:${server.address().port}`;

(async()=>{
 const browser=await chromium.launch({headless:true,...(process.env.SINAN_CHROME_PATH?{executablePath:process.env.SINAN_CHROME_PATH}:{})});
 try { const outputs=[];
 for(const width of [1280,390]) {
 const context=await browser.newContext({viewport:{width,height:900}}),page=await context.newPage(),errors=[],posts=[],regionWrites=[];
 page.on('pageerror',e=>errors.push(e.message));
 let targetFailure = false, diagnosticFailure = false, ready = true, cancelPosts = 0;
 const now=Math.floor(Date.now()/1000),target={id:'2e1a5a79-0b58-4f72-95d9-b998d7d73e68',name:'受控目标',target:'example.test',port:443,carrier:'',region:null};
 let reports=[{id:'partial',status:'failed',agent_completed:true,cancel_requested_at:null,cancel_error:null,job:{plugin:'tcpquality',version:'0.3.0-TEST_ONLY-r1',options:{ip_version:'4',count:'4',concurrency:'1'},tcpquality:{region:'configured',targets:[{...target}]}},report:null,error:'夹具部分未完成',created_at:now-30,updated_at:now,expires_at:now+300,expected_sections:['tcp_scope','tcp_summary','tcp_target_2e1a5a790b584f7295d9b998d7d73e68','environment'],report_completeness:'partial',sections:[{name:'tcp_target_2e1a5a790b584f7295d9b998d7d73e68',complete:true,revision:1,collected_at:now,text:JSON.stringify({target,address:null,complete:true,summary:{attempted:4,succeeded:0,connection_success_percent:0,latency_mean_ms:null},error:'连接超时'})}]},{id:'node-history',status:'succeeded',agent_completed:true,job:{plugin:'nodequality',options:{}},report:{text:'LEGACY_NODE_HISTORY_MUST_NOT_SHOW'}}];
 const finishedTarget={...target,name:'完成结果目标'};
 const finalResult={target:finishedTarget,address:'192.0.2.1',complete:true,summary:{attempted:4,succeeded:4,connection_success_percent:100,latency_mean_ms:25,latency_min_ms:20,latency_max_ms:30},error:null};
 reports.push({...reports[0],id:'complete-report',status:'succeeded',error:null,job:{...reports[0].job,tcpquality:{region:'configured',targets:[finishedTarget]}},report:{text:JSON.stringify({engine:{source_commit:'TEST_ONLY'},started_at_ms:(now-20)*1000,finished_at_ms:now*1000,targets:[finalResult]})},sections:[{name:'tcp_target_2e1a5a790b584f7295d9b998d7d73e68',complete:false,revision:1,collected_at:now-10,text:JSON.stringify({...finalResult,complete:false,summary:{attempted:1,succeeded:0,connection_success_percent:0,latency_mean_ms:null}})}]});
 const zeroTarget={...target,name:'零耗时目标'};
 reports.push({...reports[0],id:'zero-report',status:'succeeded',error:null,job:{...reports[0].job,tcpquality:{region:'configured',targets:[zeroTarget]}},report:{text:JSON.stringify({targets:[{...finalResult,target:zeroTarget,summary:{attempted:4,succeeded:4,connection_success_percent:100,latency_mean_ms:0,latency_min_ms:0,latency_max_ms:0}}]})},sections:[]});
 reports.push({id:'legacy-node-history',status:'succeeded',agent_completed:true,job:{options:{}},report:{text:'LEGACY_MISSING_PLUGIN_MUST_NOT_SHOW'}});
 await page.route('**/api/**',async route=>{
 const req=route.request(),path=new URL(req.url()).pathname;let data={};
 if(path==='/api/dashboard/access') data={authenticated:true,public_dashboard:false};
 else if(path==='/api/me') data={authenticated:true};
 else if(path==='/api/servers/1')data={id:1,name:'TCP 验收节点',static_info:{},online:true};
 else if(path==='/api/servers/1/diagnostics'){if(diagnosticFailure){await route.fulfill({status:403,json:{error:'DIAGNOSTICS_DENIED_FIXTURE'}});return;}data={cancel_supported:true,plugins:[{plugin:'tcpquality',title:'TCP',version:'fixture',ready,reason:ready?null:'Agent 当前离线'}],reports};}
 else if(path==='/api/plugins/tcpquality/servers/1/targets'){ if(targetFailure){await route.fulfill({status:403,json:{error:'TARGETS_DENIED_FIXTURE'}});return;}data=[target];}
 else if(path.includes('/targets/')&&req.method()==='PATCH'){const body=req.postDataJSON();regionWrites.push(body);target.region=body.region;data={saved:true};}
 else if(path==='/api/servers/1/diagnostics/tcpquality'&&req.method()==='POST'){const body=req.postDataJSON();posts.push(body);const rec={...reports[0],id:'new',status:'queued',agent_completed:false,sections:[],error:null,report_completeness:'empty',job:{...reports[0].job,options:{ip_version:body.ip_version,count:String(body.count),concurrency:String(body.concurrency)},tcpquality:{region:body.region,targets:[{...target}]}}};reports.unshift(rec);data=rec;}
 else if(path==='/api/servers/1/diagnostics/new/cancel'){if(req.method()!=='POST')throw Error('Cancel method invalid');cancelPosts++;reports[0].status='cancel_requested';data=reports[0];}
 else throw Error('Unexpected API '+path);
 await route.fulfill({json:data});
 });
 await page.goto(`${origin}/#/servers/1/tcp-quality`);
 await page.getByRole('heading',{name:'TCP 连接诊断'}).waitFor();
 const completed=page.locator('article.quality-report').filter({hasText:'完成结果目标'});
 if(!(await completed.innerText()).includes('100.00%') || !(await completed.innerText()).includes('均值 25.00 ms')) throw Error('Old partial chapter downgraded completed report');
 const text=await page.locator('body').innerText();if(!text.includes('0.00%')||!text.includes('均值 未知')||text.includes('LEGACY_NODE_HISTORY_MUST_NOT_SHOW')||text.includes('LEGACY_MISSING_PLUGIN_MUST_NOT_SHOW'))throw Error('Partial/unknown/history invalid');
 if(!(await page.locator('article.quality-report').filter({hasText:'零耗时目标'}).innerText()).includes('均值 0.00 ms'))throw Error('Real zero latency was hidden');
 await page.getByText('配置目标地区',{exact:true}).click();await page.getByLabel('受控目标地区').selectOption('east_asia');
 await page.getByLabel('目标地区',{exact:true}).selectOption('east_asia');await page.getByLabel('IP 版本',{exact:true}).selectOption('6');
 await page.getByLabel('每目标连接次数',{exact:true}).selectOption('8');await page.getByLabel('最大并发',{exact:true}).selectOption('2');
 await page.getByRole('button',{name:'开始 TCP 诊断',exact:true}).click();await page.getByText('等待设备领取',{exact:true}).waitFor();
 if(JSON.stringify(posts)!==JSON.stringify([{region:'east_asia',ip_version:'6',count:8,concurrency:2}]))throw Error('Whitelist request invalid');
 await page.getByLabel('受控目标地区').selectOption('europe');
 const frozen=await page.locator('article.quality-report').filter({hasText:'等待设备领取'}).innerText();
 if(!frozen.includes('IPv6 · 每目标 8 次 · 2 并发 · 东亚')||!frozen.includes('东亚 / 运营商未知')||frozen.includes('欧洲'))throw Error('Live target edit changed frozen task scope');
 reports[0].status='cleaning';reports[0].error='测试执行结束，残留挂载等待清理';
 await page.reload();await page.getByText('等待设备确认清理',{exact:true}).waitFor();
 if(!(await page.getByRole('button',{name:'开始 TCP 诊断',exact:true}).isDisabled()))throw Error('Automatic cleanup released shared diagnostic mutex');
 if(!(await page.getByText('测试执行结束，残留挂载等待清理',{exact:true}).isVisible()))throw Error('Cleanup cause missing');
 if(!(await completed.innerText()).includes('均值 25.00 ms'))throw Error('Automatic cleanup hid existing report');
 await page.getByRole('button',{name:'请求取消测试',exact:true}).click();await page.getByText('等待设备确认取消',{exact:true}).first().waitFor();
 if(!(await page.getByRole('button',{name:'开始 TCP 诊断',exact:true}).isDisabled()))throw Error('Cancel barrier invalid');
 if(!(await page.locator('.quality-options').evaluate(el=>el.getBoundingClientRect().right<=innerWidth)))throw Error('Mobile controls overflow');
 if(process.env.SINAN_UI_SCREENSHOT_DIR)await page.screenshot({path:resolve(process.env.SINAN_UI_SCREENSHOT_DIR,`sinan-tcp-ui-${width}.png`),fullPage:true});
 if(cancelPosts!==1)throw Error('Unexpected duplicate cancel');
 reports=reports.filter(record=>record.id!=='new');
 await page.reload();await page.getByRole('button',{name:'开始 TCP 诊断',exact:true}).waitFor();
 diagnosticFailure=true;
 await page.getByText('DIAGNOSTICS_DENIED_FIXTURE',{exact:true}).waitFor({timeout:10000});
 if(!(await page.getByRole('button',{name:'开始 TCP 诊断',exact:true}).isDisabled()))throw Error('Denied diagnostic polling reused stale readiness for creation');
 if(!(await page.getByText('当前诊断状态未知，无法确认设备能力或正在执行的任务；状态恢复前暂停创建。',{exact:true}).isVisible()) || !(await completed.innerText()).includes('均值 25.00 ms'))throw Error('Denied diagnostic polling hid history or failed to show unknown readiness');
 diagnosticFailure=false;
 await page.getByText('DIAGNOSTICS_DENIED_FIXTURE',{exact:true}).waitFor({state:'hidden',timeout:10000});
 if(!(await page.getByRole('button',{name:'开始 TCP 诊断',exact:true}).isEnabled()))throw Error('Recovered diagnostic polling did not restore current readiness');
 targetFailure=true;
 await page.getByText('TARGETS_DENIED_FIXTURE',{exact:true}).waitFor({timeout:10000});
 const unavailable=await page.locator('body').innerText();
 if(unavailable.includes('本次将冻结 0 个目标') || unavailable.includes('本次将冻结 1 个目标') || unavailable.includes('没有已启用的 TCP 拨测目标'))throw Error('Failed target read misreported current configuration');
 if(!unavailable.includes('尚未取得目标列表，本次目标数未知') || !(await completed.innerText()).includes('均值 25.00 ms'))throw Error('Failed target read hid history or failed to show unknown scope');
 if(!(await page.getByRole('button',{name:'开始 TCP 诊断',exact:true}).isDisabled()))throw Error('Failed target read did not prevent creation');
 targetFailure=false;ready=false;await page.reload();await page.getByText('Agent 当前离线',{exact:true}).waitFor();
 if(!(await page.getByRole('button',{name:'开始 TCP 诊断',exact:true}).isDisabled()))throw Error('Offline agent allowed creation');
 if(errors.length)throw Error(errors.join(';'));outputs.push({width,errors:errors.length,posts:posts.length,regionWrites:regionWrites.length,partialVisible:true,unknownLatency:true,realZeroLatency:true,legacyFiltered:true,frozenScope:true,cancelBarrier:true,automaticCleanupBarrier:true,completePreserved:true,diagnosticPoll403Disabled:true,diagnosticRecovery:true,failedPollingKeepsHistory:true,targetPoll403Unknown:true,offlineDisabled:true});
 await context.close();
 }
 console.log(JSON.stringify(outputs)); } finally { await browser.close(); await new Promise(resolve=>server.close(resolve)); }
})().catch(e=>{console.error(e);process.exit(1)});
