import { newQuickJSWASMModule, newVariant, RELEASE_SYNC } from 'quickjs-emscripten';
import wasmLocation from '@jitl/quickjs-wasmfile-release-sync/wasm?url';
import { evaluateScript, type ScriptInput } from './replay-script-engine';
self.onmessage=async(event:MessageEvent<ScriptInput>)=>{
 try{const engine=await newQuickJSWASMModule(newVariant(RELEASE_SYNC,{wasmLocation}));self.postMessage(evaluateScript(engine,event.data));}
 catch(error){self.postMessage({logs:[],updates:{},error:error instanceof Error?error.message:'Script engine unavailable'});}
};
