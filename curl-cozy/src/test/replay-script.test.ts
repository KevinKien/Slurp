import { describe,it,expect,beforeAll } from 'vitest';
import { getQuickJS, type QuickJSWASMModule } from 'quickjs-emscripten';
import { evaluateScript } from '../lib/replay-script-engine';
let engine:QuickJSWASMModule;
beforeAll(async()=>{engine=await getQuickJS();});
const run=(source:string,variables:Record<string,string>={})=>evaluateScript(engine,{source,variables,response:{status:200,body:'{"data":{"access_token":"abc"}}',headers:{'content-type':'application/json'}}});
describe('isolated after response scripts',()=>{
 it('extracts tokens into independent shared names',()=>{const a=run('variables.set("token1",response.json().data.access_token);console.log(response.status)');expect(a.updates).toEqual({token1:'abc'});expect(a.logs).toEqual(['log: 200']);expect(run('variables.set("token2",variables.get("token1")+"2")',a.updates).updates).toEqual({token2:'abc2'});});
 it('rolls back all writes on failure',()=>{expect(run('variables.set("token1","new");throw Error("failed")',{token1:'old'})).toMatchObject({updates:{},error:'failed'});});
 it('interrupts infinite loops',()=>{expect(run('while(true){}').error).toBeTruthy();});
 it('does not expose browser, network or node globals',()=>{expect(run('console.log(typeof fetch,typeof window,typeof process,typeof XMLHttpRequest)').logs).toEqual(['log: undefined undefined undefined undefined']);});
 it('rejects invalid values and async scripts',()=>{expect(run('variables.set("bad name","x")').error).toBeTruthy();expect(run('return Promise.resolve(1)').error).toBeTruthy();});
 it('bounds guest allocations',()=>{expect(run('let a=[];while(true)a.push("x".repeat(100000))').error).toBeTruthy();});
});

import { normalizeStoredTabs, serializeTabs } from '../lib/replay-tabs';
it('persists scripts per tab and excludes execution output',()=>{
 const tabs=[{id:1,name:'Login A',afterResponse:'variables.set("token1","a")',request:{method:'POST',url:'https://example.com/login',headers:{},body:''},scriptResult:{logs:[],updates:{token1:'a'}}}];
 const doc=serializeTabs(tabs,1);
 expect(normalizeStoredTabs(doc)[0]?.afterResponse).toBe(tabs[0]?.afterResponse);
 expect(doc.tabs[0]).not.toHaveProperty('scriptResult');
});
