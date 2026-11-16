import {test,expect} from '@playwright/test';
import fs from 'node:fs';
const safeUrl=(value)=>{try{const url=new URL(value);return url.origin+url.pathname;}catch{return '[invalid URL]';}};
test.beforeEach(async({page},testInfo)=>{
  const events=[];
  page.on('response',response=>events.push({event:'response',url:safeUrl(response.url()),status:response.status()}));
  page.on('requestfailed',request=>events.push({event:'requestfailed',url:safeUrl(request.url()),error:request.failure()?.errorText}));
  testInfo.safeEvents=events;
});
test.afterEach(async({page},testInfo)=>{
  if(testInfo.status===testInfo.expectedStatus)return;
  fs.mkdirSync('diagnostics',{recursive:true});
  const snapshot={test:testInfo.title,url:safeUrl(page.url()),events:testInfo.safeEvents};
  // Visible text excludes form field values, hidden inputs and network token responses.
  snapshot.visibleText=await page.locator('body').innerText().catch(()=>'[unavailable]');
  fs.writeFileSync('diagnostics/browser-'+testInfo.testId.replace(/[^a-zA-Z0-9]/g,'_')+'.json',JSON.stringify(snapshot,null,2));
});
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

test('native public client exchanges authorization code with S256 verifier and no secret',async({page,request})=>{
  const {randomBytes,createHash}=await import('node:crypto');
  const verifier=randomBytes(32).toString('base64url');
  const challenge=createHash('sha256').update(verifier).digest('base64url');
  const state=randomBytes(24).toString('hex');
  const nonce=randomBytes(24).toString('hex');
  const redirect='https://native.localhost:3002/auth/callback';
  const auth=new URL(process.env.OIDC_ISSUER+'/protocol/openid-connect/auth');
  for(const [key,value] of Object.entries({client_id:'sdk-native',redirect_uri:redirect,response_type:'code',scope:'openid',code_challenge:challenge,code_challenge_method:'S256',state,nonce}))auth.searchParams.set(key,value);
  await page.goto(auth.href);
  await page.locator('#username').fill(process.env.OIDC_TEST_USERNAME);
  await page.locator('#password').fill(process.env.OIDC_TEST_PASSWORD);
  await page.locator('#kc-login').click();
  await page.waitForURL(url=>url.origin==='https://native.localhost:3002' && url.pathname==='/auth/callback');
  const callback=new URL(page.url());
  expect(callback.searchParams.get('state')).toBe(state);
  const response=await request.post(process.env.OIDC_ISSUER+'/protocol/openid-connect/token',{form:{
    grant_type:'authorization_code',client_id:'sdk-native',redirect_uri:redirect,
    code:callback.searchParams.get('code'),code_verifier:verifier
  }});
  expect(response.status()).toBe(200);
  const tokens=await response.json();
  expect(tokens.token_type.toLowerCase()).toBe('bearer');
  expect(tokens.id_token).toBeTruthy();
  const refreshGrant=await request.post(process.env.OIDC_ISSUER+'/protocol/openid-connect/token',{form:{
    grant_type:'refresh_token',client_id:'sdk-native',refresh_token:tokens.refresh_token
  }});
  expect(refreshGrant.status()).toBe(200);
  const rotated=await refreshGrant.json();
  expect(rotated.refresh_token !== tokens.refresh_token).toBe(true);
  const replay=await request.post(process.env.OIDC_ISSUER+'/protocol/openid-connect/token',{form:{
    grant_type:'refresh_token',client_id:'sdk-native',refresh_token:tokens.refresh_token
  }});
  expect(replay.status()).toBe(400);
  expect((await replay.json()).error).toBe('invalid_grant');

  // Payload assertion checks nonce propagation, not signature validation.
  expect(JSON.parse(Buffer.from(tokens.id_token.split('.')[1],'base64url').toString()).nonce).toBe(nonce);
});

test('RP global logout delivers signed backchannel and clears provider SSO',async({page,context})=>{
  await page.goto('https://one.localhost:3000/login');
  await page.locator('#username').fill(process.env.OIDC_TEST_USERNAME);
  await page.locator('#password').fill(process.env.OIDC_TEST_PASSWORD);
  await page.locator('#kc-login').click();
  await page.waitForURL('https://one.localhost:3000/account');
  const second=await context.newPage();
  await second.goto('https://two.localhost:3001/login');
  await second.waitForURL('https://two.localhost:3001/account');
  await page.goto('https://one.localhost:3000/global-logout-form');
  await page.getByRole('button',{name:'Global logout',exact:true}).click();
  await page.waitForURL('https://one.localhost:3000/');
  // Fake Broker always returns active=true: only the validated signed event can deny app two.
  await expect.poll(async()=>(await second.request.get('https://two.localhost:3001/account')).status()).toBe(401);
  await page.goto('https://one.localhost:3000/login');
  await expect(page.locator('#username')).toBeVisible();
});

test('SDK refresh rotates confidential credentials twice and records registry lifecycle',async({page})=>{
  await page.goto('https://one.localhost:3000/login');
  await page.locator('#username').fill(process.env.OIDC_TEST_USERNAME);
  await page.locator('#password').fill(process.env.OIDC_TEST_PASSWORD);
  await page.locator('#kc-login').click();
  await page.waitForURL('https://one.localhost:3000/account');
  const before=await (await page.request.get('https://one.localhost:3000/lifecycle-operations')).json();
  const previous=before.filter(operation=>operation==='refreshed').length;
  for(let iteration=0;iteration<2;iteration++){
    await page.goto('https://one.localhost:3000/refresh-form');
    await page.getByRole('button',{name:'Refresh session',exact:true}).click();
    await page.waitForURL('https://one.localhost:3000/account');
    expect(await page.locator('body').innerText()).toContain('synthetic-person');
  }
  const operations=await (await page.request.get('https://one.localhost:3000/lifecycle-operations')).json();
  expect(operations.filter(operation=>operation==='refreshed').length).toBe(previous+2);
  expect(operations).toContain('registered');
});
