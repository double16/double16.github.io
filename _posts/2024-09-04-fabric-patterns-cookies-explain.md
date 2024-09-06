---
layout: post
title:  "AI Bot for Explaining Cookies"
date:   2024-09-04 16:00:00 -0500
categories:
  - cyber
  - recon
  - ai
comments: true
---

Artificial Intelligence (AI) gets a lot of attention. I was skeptical at first, but after using
ChatGPT instead of DuckDuckGo, I was impressed. After asking for it to write some code for me,
then I was really impressed. I recently watched [Practical AI for Bounty Hunters](https://youtu.be/DqgterfPHzg?si=cLEZo9dTk5_HLUMg). Wow.

Jason Haddix presented using [fabric](https://github.com/danielmiessler/fabric) to produce AI bots
for security research. Do watch the video. He is a good presenter and there is so much useful
information you'll likely watch it more than once.

I wrote an AI bot to explain the cookies used by a site. The code is available in my GitHub at [https://github.com/double16/fabric](https://github.com/double16/fabric). The examples are from public sites, no vulnerabilities are exposed, so this is legal and ethical.

When running the bot, check the last comment for recommended `fabric` arguments. It significantly
affects the outcome.

# trip.com

I was an authenticated user on trip.com when I saved the raw request and response using ZAP. The
format is the same as Burp Suite. It includes all of the request and response headers and bodies. The bot is able to extract cookies from it.

```shell
$ cat trip.raw | fabric --pattern explain_cookies --temperature=.2 --presencepenalty=.2 --stream
```

The results were better than I expected!

## Cookie Analysis

- **UBT_VID**: This cookie seems to be used for tracking user behavior on the website. The value `1724669840943.2043fLOxwGsP` appears to be a unique identifier, possibly combining a timestamp with a random string for uniqueness.

- **ibu_online_jump_site_result**: Stores JSON data indicating user preferences or actions related to site navigation. The value `{"site_url":[],"suggestion":["en-us","","es-us"]}` suggests it's used to manage language or regional settings and suggestions.

- **ibulanguage** and **ibulocale**: Both cookies (`EN` and `en_us` respectively) are straightforward, storing the user's language and locale preferences, which help in customizing the user interface according to the user's preferred language.

- **cookiePricesDisplayed**: Stores the currency preference (`USD`) for displaying prices, ensuring that the user sees prices in their chosen currency consistently across the site.

- **_abtest_userid**: Contains a UUID `6913d6ac-7bb1-4e89-ba0d-33858f62ac07`, likely used to identify a user in A/B testing scenarios to deliver consistent experiment experiences.

- **_gid**, **_gcl_au**, **_ga**, **_ga_2DCSB93KS4**, **_ga_37RNVFDP1J**, **_ga_X437DZ73MR**: These are Google Analytics cookies used to distinguish users and sessions for analytics purposes. The values are identifiers and timestamps related to user sessions and interactions.

- **_tt_enable_cookie** and **_ttp**: Related to tracking technologies, possibly for advertising or user behavior tracking. The values `1` and `o2HwmvRJ9YAEV4WeLYhEOgxmzD6` suggest an enabled state and a unique tracking ID.

- **_RSG**, **_RDG**, **_RGUID**: Seem to be related to session or user identification with specific values like `hpas6yHluMDYVCpjKpIO39` and `d5b8bd1f-06da-4ceb-90d8-4b352dccc7e2` which could be used internally for maintaining user session states or logs.

- **GUID**: `09034024316925335983` appears to be a globally unique identifier for the user or session, critical for linking back-end processes to the user.

- **login_type**, **login_uid**, **DUID**: These cookies (`0`, `B2E7EBBB91A228E959D2AE549E4265610FC51D2A7E3F2BBD187B34B46FE68E99C4288992DDE5C7C3369410D38AE6B9F4`, `u=6D6E7DE4CA24C7AD5F0E32C02BACD288C3473027A632936E861D6B4023D2505C&v=0`) are highly sensitive as they relate to user authentication and device identification. Exposure of these values can lead to account takeover or identity theft.

- **_udl**: Appears to be an encrypted or hashed value `CC0F7EF1FB3BF3A3EA7122B403EF204C`, possibly related to user login or session details, indicating a high confidentiality requirement.

- **_bfa**, **_bfi**, **_bfaStatusPVSend**, **_bfaStatus**: These cookies are likely used for analytics or fraud detection, with values indicating various statuses and identifiers for tracking user interactions and behaviors.

## Cookie Interactions

The interaction between cookies like `_ga`, `_gid`, `_gcl_au` (all Google Analytics), and `_abtest_userid` suggests a comprehensive tracking system for user behavior analysis and site optimization based on user activities. The GUID and login-related cookies interact to maintain session integrity and secure user authentication processes.

## Security Concerns

The most sensitive cookies here are `login_uid`, `DUID`, and `_udl`, which should be protected to prevent session hijacking and identity theft. The use of HTTPS is crucial to protect these cookies from being exposed during data transmission. Additionally, setting cookies with the `HttpOnly` and `Secure` flags would help mitigate the risk of client-side script access and ensure they are sent over secure channels, respectively. The exposure of these values can lead to significant security breaches, including unauthorized access to user accounts and personal data.


# 6sense.com

Let's try another one, except using the HTTP Archive Format (HAR). It is a JSON format supported
by many tools. Chrome and Firefox support saving  this format from dev tools, as well as ZAP
and Burp Suite.

```shell
$ cat 6sense-vdp.har | fabric --pattern explain_cookies --temperature=.2 --presencepenalty=.2  --stream
```

### Cookie Analysis

- **__cf_bm**: This cookie is associated with Cloudflare and is used to distinguish between humans and bots. This is beneficial for the website, to make valid reports on the use of their site. It also contains a unique ID that Cloudflare uses to identify individual clients behind a shared IP address and apply security settings on a per-client basis.

- **__q_state_nev3mYP3YV7DaW2F**: Appears to be a custom cookie used to store state information in a JSON encoded format. The value includes a UUID and a domain, suggesting it's used for tracking user sessions or preferences across the domain "6sense.com".

- **_fbp**: This cookie is set by Facebook to deliver advertisement products such as real time bidding from third party advertisers. It contains identifiers for the browser and a unique visitor ID.

- **_ga**: This Google Analytics cookie is used to distinguish unique users by assigning a randomly generated number as a client identifier. It is included in each page request in a site and used to calculate visitor, session and campaign data for the sites analytics reports.

- **_ga_311340212**, **_ga_JKCB2CTS3D**, **_ga_Q57CXMB28P**: These are Google Analytics cookies used to manage user sessions. They typically contain timestamp details of when a visitor enters and leaves the website, along with session identifiers.

- **_gcl_au**: Used by Google AdSense for experimenting with advertisement efficiency across websites using their services.

- **_ketch_consent_v1_**: This cookie seems to be related to managing user consent for various services and tracking. The encoded value suggests detailed consent preferences for analytics, advertising, and functional services.

- **_mkto_trk**: This cookie is associated with an email marketing service provided by Marketo. It tracks the visitor's identity and behavior on the website to optimize the relevance of marketing campaigns.

- **_pf_id.c97b** and **_pf_ses.c97b**: Likely used for tracking user behavior and session details. The complex structure suggests it includes timestamps, unique identifiers, and possibly session states.

- **_swb** and **_swb_consent_**: These cookies seem to manage user consent settings for various tracking or functional services, possibly related to a web-based application or service.

- **_uetsid** and **_uetvid**: These cookies are used by Microsoft Bing Ads and are used for tracking the success of advertising campaigns on Bing.

- **cf_clearance**: This cookie is related to Cloudflare and is used to bypass security restrictions based on the visitor coming from a trusted IP address.

- **mutiny.user.session**, **mutiny.user.session_number**, **mutiny.user.token**: These appear to be custom cookies used to manage user sessions and authentication tokens, likely for maintaining session state and security across page requests.

- **vid**: Likely a unique visitor ID, used for tracking purposes to distinguish different visitors.

### Cookie Interactions

The interactions between these cookies are primarily focused on tracking, user identification, session management, and advertising. For instance, Google Analytics cookies (_ga, _ga_311340212, _ga_JKCB2CTS3D, _ga_Q57CXMB28P) work together to provide a comprehensive view of how users interact with the site over time. The _fbp and _gcl_au cookies interact by contributing data for advertising efficiency analytics. The mutiny.user.* cookies interact to maintain a secure and continuous user session.

### Security Concerns

1. **Exposure of Session Tokens**: Cookies like `mutiny.user.token` carry session tokens which, if exposed, could allow an attacker to hijack a user's session.
2. **Third-Party Tracking**: Cookies such as `_fbp` and Google Analytics cookies can track user behavior across different sites, which raises privacy concerns.
3. **Persistent Identifiers**: Cookies like `vid` and `_uetvid` that serve as persistent identifiers can be used to track users over long periods, potentially infringing on privacy if not properly managed and disclosed.
4. **Encryption and Encoding**: Values in cookies like `_ketch_consent_v1_` are encoded, which is good for security. However, it's crucial that sensitive information is not only encoded but encrypted to prevent unauthorized access.

It's essential for users to be aware of these cookies, understand their purpose, and manage their consent preferences to protect their privacy and data integrity.

# Conclusion

I could search all of these cookie names myself. At some point I will see enough of them to know
by memory. The value add is that this bot is a single command and the output is great for pasting into notes. How much time would I spend searching, researching and assembling this myself? I
will be certainly be using AI bots moving forward. I will be adding to [https://github.com/double16/fabric](https://github.com/double16/fabric) as I develop more bots.

