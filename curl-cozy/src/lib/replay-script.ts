import type { ScriptInput, ScriptResult } from './replay-script-engine';
export function runReplayScript(input:ScriptInput):Promise<ScriptResult>{
 return new Promise(resolve=>{
  let worker:Worker;
  try{worker=new Worker(new URL('./replay-script.worker.ts',import.meta.url),{type:'module'});}catch{resolve({logs:[],updates:{},error:'Script worker unavailable'});return;}
  const finish=(result:ScriptResult)=>{clearTimeout(timer);worker.terminate();resolve(result);};
  const timer=setTimeout(()=>finish({logs:[],updates:{},error:'Script execution timed out'}),3000);
  worker.onmessage=event=>finish(event.data as ScriptResult);
  worker.onerror=()=>finish({logs:[],updates:{},error:'Script worker failed'});
  worker.postMessage(input);
 });
}
