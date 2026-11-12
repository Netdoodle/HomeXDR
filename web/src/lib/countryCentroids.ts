// Approximate centre of each country (ISO 3166-1 alpha-2 → latitude, longitude), rounded to
// a degree or so: enough to place a bubble on the dot map. Kept in the source so the map makes
// no outside requests.

const RAW =
  'AD:42.5,1.5;AE:24,54;AF:33,66;AG:17,-61.8;AI:18.2,-63;AL:41,20;AM:40,45;AO:-12.5,18.5;AR:-34,-64;AS:-14.3,-170;' +
  'AT:47.3,13.3;AU:-25,134;AW:12.5,-70;AX:60.2,20;AZ:40.5,47.5;BA:44,18;BB:13.2,-59.5;BD:24,90;BE:50.8,4;BF:13,-2;' +
  'BG:43,25;BH:26,50.5;BI:-3.5,30;BJ:9.5,2.3;BM:32.3,-64.8;BN:4.5,114.7;BO:-17,-65;BR:-10,-52;BS:24.3,-76;BT:27.5,90.5;' +
  'BW:-22,24;BY:53,28;BZ:17.3,-88.8;CA:57,-100;CD:-3,23;CF:7,21;CG:-1,15;CH:47,8;CI:7.5,-5.5;CK:-21.2,-159.8;CL:-31,-71;' +
  'CM:6,12;CN:35,104;CO:4,-73;CR:10,-84;CU:21.5,-79;CV:16,-24;CW:12.2,-69;CY:35,33;CZ:49.8,15.5;DE:51,10;DJ:11.5,43;' +
  'DK:56,10;DM:15.4,-61.4;DO:19,-70.7;DZ:28,3;EC:-1.5,-78;EE:59,26;EG:27,30;ER:15,39;ES:40,-4;ET:8,38;FI:64,26;FJ:-18,178;' +
  'FO:62,-7;FR:46,2;GA:-1,11.8;GB:54,-2;GD:12.1,-61.7;GE:42,43.5;GF:4,-53;GG:49.5,-2.5;GH:8,-1.2;GI:36.1,-5.4;GL:72,-40;' +
  'GM:13.5,-15.5;GN:10,-11;GP:16.2,-61.6;GQ:2,10;GR:39,22;GT:15.5,-90.3;GU:13.4,144.8;GW:12,-15;GY:5,-59;HK:22.3,114.2;' +
  'HN:15,-86.5;HR:45.2,15.5;HT:19,-72.4;HU:47,20;ID:-2,118;IE:53,-8;IL:31.5,35;IM:54.2,-4.5;IN:22,79;IQ:33,44;IR:32,53;' +
  'IS:65,-18;IT:42.8,12.8;JE:49.2,-2.1;JM:18.2,-77.3;JO:31,36;JP:36,138;KE:0.5,38;KG:41.5,75;KH:12.5,105;KI:1.4,173;' +
  'KM:-12,44;KN:17.3,-62.7;KP:40,127;KR:36.5,128;KW:29.3,47.6;KY:19.3,-81.2;KZ:48,68;LA:18,105;LB:33.8,35.8;LC:13.9,-61;' +
  'LI:47.2,9.5;LK:7.5,80.7;LR:6.5,-9.5;LS:-29.5,28.2;LT:55.3,24;LU:49.7,6.1;LV:57,25;LY:27,17;MA:32,-6;MC:43.7,7.4;' +
  'MD:47,28.5;ME:42.7,19.3;MG:-19,46.7;MH:7.1,171;MK:41.6,21.7;ML:17,-4;MM:21,96;MN:46.5,104;MO:22.2,113.5;MQ:14.6,-61;' +
  'MR:20,-10.5;MT:35.9,14.4;MU:-20.3,57.6;MV:3.2,73.2;MW:-13.5,34;MX:23,-102;MY:4,102;MZ:-18,35;NA:-22,17;NC:-21.3,165.5;' +
  'NE:17,9;NG:9,8;NI:12.9,-85;NL:52.3,5.5;NO:62,10;NP:28,84;NZ:-41,174;OM:21,57;PA:9,-80;PE:-10,-76;PF:-17.7,-149.4;' +
  'PG:-6,147;PH:12,122;PK:30,70;PL:52,19.5;PR:18.2,-66.5;PS:31.9,35.2;PT:39.5,-8;PW:7.5,134.5;PY:-23,-58;QA:25.3,51.2;' +
  'RE:-21.1,55.5;RO:46,25;RS:44,21;RU:60,90;RW:-2,30;SA:24,45;SB:-9,160;SC:-4.6,55.5;SD:15,30;SE:62,15;SG:1.35,103.8;' +
  'SI:46,15;SK:48.7,19.5;SL:8.5,-11.8;SM:43.9,12.4;SN:14.5,-14.5;SO:5,46;SR:4,-56;SS:7,30;ST:0.2,6.6;SV:13.8,-88.9;' +
  'SX:18,-63;SY:35,38;SZ:-26.5,31.5;TC:21.7,-71.8;TD:15,19;TG:8,1.2;TH:15,101;TJ:39,71;TL:-8.8,125.7;TM:39,59.5;TN:34,9;' +
  'TO:-20,-175;TR:39,35;TT:10.5,-61.3;TW:23.7,121;TZ:-6,35;UA:49,32;UG:1.3,32.3;US:39,-98;UY:-33,-56;UZ:41.5,64;' +
  'VA:41.9,12.45;VC:13.2,-61.2;VE:7,-66;VG:18.4,-64.6;VI:18.3,-64.9;VN:16,107;VU:-16,167;WS:-13.8,-172;XK:42.6,21;' +
  'YE:15.5,48;YT:-12.8,45.2;ZA:-29,24;ZM:-14,27.8;ZW:-19,29.8;EU:50,10;AP:15,105'

export const COUNTRY_CENTROIDS: Record<string, [number, number]> = Object.fromEntries(
  RAW.split(';').map((e) => {
    const [cc, ll] = e.split(':')
    const [lat, lon] = ll.split(',').map(Number)
    return [cc, [lat, lon] as [number, number]]
  }),
)

let names: Intl.DisplayNames | null = null

/** The country's name in the browser's language, or the code when unknown. */
export function countryName(code?: string): string {
  if (!code) return 'Unknown'
  if (code === 'EU') return 'Europe (unspecified)'
  if (code === 'AP') return 'Asia-Pacific (unspecified)'
  try {
    names ??= new Intl.DisplayNames(undefined, { type: 'region' })
    return names.of(code.toUpperCase()) ?? code
  } catch {
    return code
  }
}
