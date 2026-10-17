import type { HttpRequest } from './traffic';
export function isWebSocketRequest(request: Pick<HttpRequest,'url'|'headers'>): boolean {
  return /^wss?:\/\//i.test(request.url) || Object.entries(request.headers).some(([k,v])=>k.toLowerCase()==='upgrade'&&v.toLowerCase()==='websocket');
}
export function websocketRequest(request: HttpRequest): HttpRequest {
  return {...request,method:'GET',url:request.url.replace(/^http:/i,'ws:').replace(/^https:/i,'wss:'),headers:{...Object.fromEntries(Object.entries(request.headers).filter(([k])=>k.toLowerCase()!=='upgrade')),Upgrade:'websocket'}};
}
