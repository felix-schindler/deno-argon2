import { verify } from "@felix/argon2";

const hash =
	"$argon2i$v=19$m=4096,t=3,p=1$AQIDBAUGBwg$u87PDHPaaimrdwCIQSwMxRQgjo22ufjWoL3urtrePU0";

console.log(await verify(hash, "test"));
