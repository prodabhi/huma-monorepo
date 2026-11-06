// What a writer does in place on their own page (/@handle, pages/writer.mjs), signed with this browser's key as /write
// signs it (account.mjs), without loading the editor: hiding a page from it.
import { account, shortTarget, setListed } from './account.mjs';

/** Takes the page with this short link code off the writer's page (its link keeps working). */
export async function hide(code) {
  if (!account()) throw new Error('Sign in to change this page.');
  const id = await shortTarget('/p/' + code);
  if (!id) throw new Error('Couldn’t find this page. It may be deleted already.');
  await setListed(id, false);
}
