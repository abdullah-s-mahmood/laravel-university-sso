import {test,expect} from '@playwright/test';
test('two independent consumers: PKCE login, SSO, local logout, redirect rejection',async({page,context})=>{
  const issuer=process.env.OIDC_ISSUER;
  await page.goto('https://one.localhost:3000/login');
  await expect(page.locator('#username')).toBeVisible();
  const auth=new URL(page.url());
  expect(auth.searchParams.get('code_challenge_method')).toBe('S256');
  expect(auth.searchParams.get('state')).toBeTruthy();
  expect(auth.searchParams.get('nonce')).toBeTruthy();
  await page.locator('#username').fill(process.env.OIDC_TEST_USERNAME);
  await page.locator('#password').fill(process.env.OIDC_TEST_PASSWORD);
  await page.locator('#kc-login').click();
  await page.waitForURL('https://one.localhost:3000/account');
  expect((await page.locator('body').innerText())).toContain('synthetic-person');
  const second=await context.newPage();
  await second.goto('https://two.localhost:3001/login');
  await second.waitForURL('https://two.localhost:3001/account');
  expect(await second.locator('#username').count()).toBe(0);
  const cookies=await context.cookies();
  expect(cookies.find(c=>c.name==='sdk_one').httpOnly).toBe(true);
  expect(cookies.find(c=>c.name==='sdk_two').secure).toBe(true);
  expect(cookies.find(c=>c.name==='sdk_one').domain).toBe('one.localhost');
  expect(cookies.find(c=>c.name==='sdk_two').domain).toBe('two.localhost');
  const oneCookies=await page.request.get('https://one.localhost:3000/observed-cookies');
  const twoCookies=await page.request.get('https://two.localhost:3001/observed-cookies');
  const seenOne=await oneCookies.json();
  const seenTwo=await twoCookies.json();
  expect(seenOne).toContain('sdk_one');
  expect(seenTwo).toContain('sdk_two');
  expect(seenOne).not.toContain('sdk_two');
  expect(seenTwo).not.toContain('sdk_one');
  await page.goto('https://one.localhost:3000/logout-form');
  await page.getByRole('button',{name:'Local logout',exact:true}).click();
  const denied=await page.goto('https://one.localhost:3000/account');
  expect(denied.status()).toBe(401);
  const retained=await second.reload();
  expect(retained.status()).toBe(200);
  // The IdP session also survives local logout.
  await page.goto('https://one.localhost:3000/login');
  await page.waitForURL('https://one.localhost:3000/account');
  const bad=new URL(issuer+'/protocol/openid-connect/auth');
  for(const [k,v] of Object.entries({client_id:process.env.OIDC_CLIENT_ONE||'sdk-one',redirect_uri:'https://one.localhost:3000/unregistered',response_type:'code',scope:'openid',code_challenge:'a'.repeat(43),code_challenge_method:'S256'}))bad.searchParams.set(k,v);
  const rejected=await page.goto(bad.href);
  expect(rejected.status()).toBeGreaterThanOrEqual(400);
  expect(page.url()).not.toContain('/unregistered');
});

test('provider rejects missing PKCE for confidential web and public native clients',async({request})=>{
  for(const [client,redirect] of [['sdk-one','https://one.localhost:3000/auth/callback'],['sdk-native','https://native.localhost:3002/auth/callback']]){
    const auth=new URL(process.env.OIDC_ISSUER+'/protocol/openid-connect/auth');
    for(const [key,value] of Object.entries({client_id:client,redirect_uri:redirect,response_type:'code',scope:'openid',state:'synthetic-state'})) auth.searchParams.set(key,value);
    const response=await request.get(auth.href,{maxRedirects:0});
    if(response.status()>=300 && response.status()<400){
      const rejected=new URL(response.headers().location);
      expect(rejected.searchParams.get('error')).toBe('invalid_request');
      expect(rejected.searchParams.get('code')).toBeNull();
    } else {
      expect(response.status()).toBeGreaterThanOrEqual(400);
      expect((await response.text()).toLowerCase()).toMatch(/pkce|code.challenge/);
    }
  }
});
