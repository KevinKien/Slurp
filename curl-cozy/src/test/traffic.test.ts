import { describe,it,expect } from 'vitest';
import { parseCurl,importTraffic,pretty } from '@/lib/traffic';
describe('Traffic imports',()=>{
 it('parses a JSON cURL request without executing shell commands',()=>{const r=parseCurl(`curl https://httpbin.org/post -X POST -H 'Content-Type: application/json' -d '{"name":"Alex"}'`);expect(r.method).toBe('POST');expect(r.headers['Content-Type']).toBe('application/json');expect(JSON.parse(r.body).name).toBe('Alex');});
 it('rejects file references and unsupported options',()=>{expect(()=>parseCurl('curl https://example.com -d @secret')).toThrow();expect(()=>parseCurl('curl https://example.com --output file')).toThrow();});
 it('imports exported JSON',()=>{const entry={id:1,method:'GET',url:'https://example.com/',headers:{},body:'',status:200,statusText:'OK',duration:10,size:2,timestamp:'2026-10-16T00:00:00Z',responseHeaders:{},responseBody:'{}'};const rows=importTraffic(JSON.stringify([entry]));expect(rows).toHaveLength(1);expect(rows[0]?.responseBody).toBe(entry.responseBody);});
 it('imports a HAR response',()=>{const rows=importTraffic(JSON.stringify({log:{entries:[{request:{method:'GET',url:'https://example.com/',headers:[]},response:{status:200,statusText:'OK',headers:[],content:{size:2,text:'{}'}},time:50}]}}));expect(rows[0]?.status).toBe(200);expect(rows[0]?.duration).toBe(50);});
 it('formats JSON',()=>expect(pretty('{"a":1}')).toContain('\n'));
});