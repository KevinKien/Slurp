import type { QuickJSWASMModule } from 'quickjs-emscripten';
import { variableName, type ReplayVariables } from './replay-features';
export interface ScriptInput { source:string; response:{status:number;body:string;headers:Record<string,string>}; variables:ReplayVariables }
export interface ScriptResult { logs:string[]; updates:ReplayVariables; error?:string }
/** No host functions are exposed to the guest interpreter. */
export function evaluateScript(engine:QuickJSWASMModule,input:ScriptInput):ScriptResult {
 const runtime=engine.newRuntime();runtime.setMemoryLimit(16*1024*1024);runtime.setMaxStackSize(256*1024);
 const deadline=Date.now()+300;runtime.setInterruptHandler(()=>Date.now()>deadline);
 const context=runtime.newContext();
 try {
  if(input.source.length>32000)throw new Error('Script exceeds 32,000 characters');
  const result=context.evalCode(`(()=>{const input=${JSON.stringify(input)};const logs=[];const updates=Object.create(null);const response=Object.freeze({status:input.response.status,headers:Object.freeze(input.response.headers),text:()=>input.response.body,json:()=>JSON.parse(input.response.body)});const variables=Object.freeze({get:name=>Object.hasOwn(updates,name)?updates[name]:Object.hasOwn(input.variables,name)?input.variables[name]:undefined,set:(name,value)=>{if(typeof name!=='string'||typeof value!=='string')throw Error('variables.set expects a name and string value');updates[name]=value;}});const console=Object.freeze(Object.fromEntries(['log','info','warn','error'].map(level=>[level,(...args)=>{if(logs.length>=100)throw Error('Log limit exceeded');logs.push(level+': '+args.map(v=>typeof v==='string'?v:JSON.stringify(v)).join(' ').slice(0,2000));}])));const log=console.log;const returned=(function(response,variables,console,log){'use strict';\n${input.source}\n})(response,variables,console,log);if(returned&&typeof returned.then==='function')throw Error('Async scripts are not supported');return JSON.stringify({logs,updates});})()`);
  if(result.error){const error=context.dump(result.error);result.error.dispose();throw new Error(error?.message??String(error));}
  const raw=context.getString(result.value);result.value.dispose();
  if(runtime.hasPendingJob())throw new Error('Async scripts are not supported');
  const output=JSON.parse(raw) as ScriptResult;
  const merged={...input.variables,...output.updates};
  if(Object.keys(merged).length>100)throw new Error('Variable limit exceeded (100)');
  for(const [name,value] of Object.entries(output.updates))if(!variableName.test(name)||typeof value!=='string'||new TextEncoder().encode(value).length>64000)throw new Error('Invalid variable name or value exceeds 64 KB');
  return output;
 }catch(error){return {logs:[],updates:{},error:error instanceof Error?error.message:'Script failed'};}
 finally{context.dispose();runtime.dispose();}
}
