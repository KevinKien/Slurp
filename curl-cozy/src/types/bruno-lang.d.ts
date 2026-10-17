/** Bruno's official parser returns data only; imported scripts are never executed. */
declare module "@usebruno/lang/v2/src/bruToJson.js" {
  const parse: (source: string) => unknown;
  export default parse;
}
declare module "@usebruno/lang/v2/src/envToJson.js" {
  const parse: (source: string) => unknown;
  export default parse;
}
