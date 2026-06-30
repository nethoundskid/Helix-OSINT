#!/usr/bin/env python3
import sys, os, re, time, json, socket, hashlib, argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

for pkg in ["requests","rich"]:
    try: __import__(pkg)
    except ImportError:
        import subprocess
        subprocess.check_call([sys.executable,"-m","pip","install",pkg,"-q"])

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.rule import Rule
from rich.align import Align
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

console = Console(highlight=False, width=92)

V  = "white"
D  = "bright_black"
A  = "yellow"
ER = "red"
OK = "green"
LK = "cyan"
LO = "bright_black"

S  = requests.Session()
S.headers.update({"User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
TO = 14

GH_TOKEN = os.environ.get("GITHUB_TOKEN","")

_report = {}   # module_name -> list of dicts

def report_add(module, data):
    _report.setdefault(module,[]).append(data)

def save_report(path):
    with open(path,"w") as f:
        json.dump(_report, f, indent=2, default=str)
    pr("helix",f"report saved → {path}", OK)

def ts():
    return f"[{D}]{datetime.now().strftime('%H:%M:%S')}[/{D}]"

def pr(tag, msg, c=V):
    console.print(f"{ts()} [{D}][{tag}][/{D}] [{c}]{msg}[/{c}]")

def pr_link(label, url):
    console.print(f"  [{D}]↳[/{D}] [{D}]{label.ljust(20)}[/{D}][{LK}]{url}[/{LK}]")

def sep(title=""):
    console.print(Rule(f" {title} " if title else "", style=D, characters="─"))

def field(t, k, v, c=V):
    if v and str(v) not in ("N/A","None","","null","False"):
        t.add_row(f"[{LO}]{k}[/{LO}]", f"[{c}]{v}[/{c}]")

def get(url, **kw):
    return S.get(url, timeout=TO, **kw)

def spin(msg):
    return Progress(SpinnerColumn(style=D),
                    TextColumn(f"[{D}]{msg}[/{D}]"), transient=True)

def tbl():
    t = Table(box=box.SIMPLE, show_header=False, padding=(0,2),
              border_style=D, show_edge=False)
    t.add_column(style=D,  width=22, no_wrap=True)
    t.add_column(style=V,  min_width=42)
    return t

def ctbl(cols):
    t = Table(box=box.SIMPLE, show_header=True, header_style=f"bold {D}",
              border_style=D, show_edge=False, padding=(0,2))
    for c in cols:
        t.add_column(c[0], style=c[1], width=c[2] if len(c)>2 else None,
                     no_wrap=len(c)>3 and c[3])
    return t

def wrap(t, title):
    console.print(Panel(t, title=f"[{A}] {title} [/{A}]",
                        border_style=D, padding=(0,1)))

def gh_headers():
    h = {"Accept":"application/vnd.github+json"}
    if GH_TOKEN:
        h["Authorization"] = f"Bearer {GH_TOKEN}"
    return h

def banner():
    os.system("clear" if os.name=="posix" else "cls")
    art = (" █░█ █▀▀ █░░ █ ▀▄▀\n"
           " █▀█ ██▄ █▄▄ █ █░█\n")
    console.print()
    console.print(Align.center(f"[{A}]{art}[/{A}]"))
    tok = f"[{OK}]token active[/{OK}]" if GH_TOKEN else f"[{D}]no token[/{D}]"
    console.print(Align.center(
        f"[{D}]osint engine   //  {tok}  //  "
        f"set tokens for higher rate limits[/{D}]"))
    console.print()

def _gh_extract_emails(username, repos, hdrs):
    """Walk recent commits across repos and collect unique author emails."""
    emails = {}   # email -> {name, repo, date}
    checked = 0
    for repo in repos[:8]:
        rname = repo.get("name","")
        try:
            rc = S.get(
                f"https://api.github.com/repos/{username}/{rname}/commits?per_page=30",
                headers=hdrs, timeout=12
            )
            if not rc.ok: continue
            for commit in rc.json():
                a = commit.get("commit",{}).get("author",{})
                email = a.get("email","")
                name  = a.get("name","")
                date  = str(a.get("date",""))[:10]
                if (email and "@" in email
                        and not email.endswith("@users.noreply.github.com")
                        and email not in emails):
                    emails[email] = {"name":name,"repo":rname,"date":date}
            checked += 1
        except: pass
        time.sleep(0.2)
    return emails

def scan_github(username):
    sep(f"github // {username}")
    hdrs = gh_headers()

    with spin("querying github api..."):
        r = get(f"https://api.github.com/users/{username}", headers=hdrs)

    if r.status_code==404: pr("err","user not found",ER); return
    if r.status_code==403: pr("err","rate limited — wait 60s or export GITHUB_TOKEN",A); return
    d = r.json()

    # ── profile ──
    t = tbl()
    field(t,"login",       d.get("login"),                             A)
    field(t,"name",        d.get("name"),                              V)
    field(t,"bio",         d.get("bio"),                               V)
    field(t,"id",          str(d.get("id")),                           D)
    field(t,"node id",     d.get("node_id"),                           D)
    field(t,"type",        d.get("type"),                              D)
    field(t,"company",     d.get("company"),                           V)
    field(t,"location",    d.get("location"),                          V)
    field(t,"profile email", d.get("email") or "(hidden)",             A)
    field(t,"blog",        d.get("blog"),                              LK)
    field(t,"twitter",     "@"+d["twitter_username"] if d.get("twitter_username") else None, V)
    field(t,"created",     str(d.get("created_at",""))[:10],           D)
    field(t,"updated",     str(d.get("updated_at",""))[:10],           D)
    field(t,"repos",       str(d.get("public_repos")),                 A)
    field(t,"gists",       str(d.get("public_gists")),                 D)
    field(t,"followers",   str(d.get("followers")),                    A)
    field(t,"following",   str(d.get("following")),                    D)
    field(t,"hireable",    str(d.get("hireable")),                     D)
    field(t,"profile",     f"https://github.com/{d.get('login')}",     LK)
    field(t,"avatar",      d.get("avatar_url"),                        D)
    wrap(t,"profile")
    report_add("github_profile", d)

    # ── repos ──
    repos = []
    with spin("fetching repositories..."):
        r2 = get(f"https://api.github.com/users/{username}/repos?sort=stars&per_page=100",
                 headers=hdrs)
    if r2.ok and r2.json():
        repos = r2.json()
        # language stats
        lang_count = {}
        total_stars = 0
        for rep in repos:
            l = rep.get("language") or "Unknown"
            lang_count[l] = lang_count.get(l,0)+1
            total_stars += rep.get("stargazers_count",0)

        rt = ctbl([("★",A,6),("repo",OK,26),("lang",D,14),
                   ("forks",D,6),("issues",D,7),("updated",D,12),("desc",V)])
        for rep in repos[:15]:
            rt.add_row(
                str(rep.get("stargazers_count",0)),
                rep.get("name","?"),
                rep.get("language") or "—",
                str(rep.get("forks_count",0)),
                str(rep.get("open_issues_count",0)),
                str(rep.get("updated_at",""))[:10],
                (rep.get("description") or "")[:45]
            )
        wrap(rt, f"repositories  (total stars: {total_stars:,})")

        # top langs
        if lang_count:
            lt2 = ctbl([("language",V,18),("repos",A,8)])
            for lang,cnt in sorted(lang_count.items(),key=lambda x:-x[1])[:8]:
                lt2.add_row(lang, str(cnt))
            wrap(lt2,"top languages")

    # ── commit email extraction ──
    if repos:
        pr("github","extracting emails from commit history (passive)...", D)
        with spin("scanning commits across top repos..."):
            emails = _gh_extract_emails(username, repos, hdrs)

        if emails:
            et = ctbl([("email",A,34),("name",V,22),("repo",D,20),("last seen",D)])
            for email,(info) in emails.items():
                et.add_row(email, info["name"], info["repo"], info["date"])
            wrap(et, f"emails found in commit history  ({len(emails)} unique)")
            report_add("github_emails", emails)
        else:
            pr("github","no public emails found in commit history (may be hidden or no commits)", D)

    # ── events ──
    with spin("fetching recent activity..."):
        r3 = get(f"https://api.github.com/users/{username}/events/public?per_page=10",
                 headers=hdrs)
    if r3.ok and r3.json():
        evts = r3.json()
        et2 = ctbl([("date",D,12),("event",A,22),("repo",D)])
        for ev in evts:
            et2.add_row(
                str(ev.get("created_at",""))[:10],
                ev.get("type","?").replace("Event",""),
                ev.get("repo",{}).get("name","?")
            )
        wrap(et2,"recent activity")

    # ── orgs ──
    with spin("fetching organizations..."):
        r4 = get(f"https://api.github.com/users/{username}/orgs", headers=hdrs)
    if r4.ok and r4.json():
        ot = ctbl([("org",A,22),("url",LK)])
        for o in r4.json():
            ot.add_row(o.get("login","?"),
                       f"https://github.com/{o.get('login','')}")
        wrap(ot,"organizations")

    # ── gists ──
    with spin("fetching gists..."):
        r5 = get(f"https://api.github.com/users/{username}/gists?per_page=8",
                 headers=hdrs)
    if r5.ok and r5.json():
        gst = ctbl([("created",D,12),("files",D,6),("desc",V,38),("url",D)])
        for g in r5.json():
            gst.add_row(
                str(g.get("created_at",""))[:10],
                str(len(g.get("files",{}))),
                (g.get("description") or "(no desc)")[:38],
                g.get("html_url","")
            )
        wrap(gst,"gists")

    # ── starred repos (interests) ──
    with spin("fetching starred repos (interests)..."):
        r6 = get(f"https://api.github.com/users/{username}/starred?per_page=10",
                 headers=hdrs)
    if r6.ok and r6.json():
        srt = ctbl([("repo",V,30),("lang",D,14),("★",A,6),("desc",D)])
        for rep in r6.json():
            srt.add_row(
                rep.get("full_name","?"),
                rep.get("language") or "—",
                str(rep.get("stargazers_count",0)),
                (rep.get("description") or "")[:40]
            )
        wrap(srt,"starred repos (interests / research areas)")

    pr_link("profile",     f"https://github.com/{username}")
    pr_link("commits",     f"https://github.com/{username}?tab=commits")
    pr_link("gitstats",    f"https://gitstats.me/{username}")

def scan_discord_server(invite):
    code = re.sub(r'^(https?://)?(discord\.gg/|discord\.com/invite/)','',
                  invite).strip().split("?")[0]
    sep(f"discord server // {code}")

    with spin(f"probing invite: {code}"):
        r = get(f"https://discord.com/api/v10/invites/{code}?with_counts=true")

    if r.status_code==404: pr("err","invalid or expired invite",ER); return
    if not r.ok: pr("err",f"http {r.status_code}",ER); return

    d  = r.json()
    g  = d.get("guild",{})
    NSFW  = ['DEFAULT','EXPLICIT','SAFE','AGE_RESTRICTED']
    VERIF = ['NONE','LOW','MEDIUM','HIGH','VERY HIGH']

    t = tbl()
    field(t,"server name",  g.get("name"),                                              A)
    field(t,"server id",    g.get("id"),                                                D)
    field(t,"description",  g.get("description"),                                       V)
    field(t,"nsfw level",   NSFW[g.get("nsfw_level",0)] if g.get("nsfw_level",0)<4 else "?", D)
    field(t,"boost tier",   str(g.get("premium_tier",0)),                               V)
    field(t,"boost count",  str(g.get("premium_subscription_count",0)),                 D)
    field(t,"verification", VERIF[g.get("verification_level",0)] if g.get("verification_level",0)<5 else "?", V)
    field(t,"members",      f'{d.get("approximate_member_count",0):,}',                 A)
    field(t,"online",       f'{d.get("approximate_presence_count",0):,}',               OK)
    ch = d.get("channel",{})
    if ch: field(t,"invite chan",f'#{ch.get("name","?")} (type {ch.get("type")})',       D)
    inv = d.get("inviter",{})
    if inv:
        disc = inv.get("discriminator","0")
        tag  = f"#{disc}" if disc and disc!="0" else ""
        field(t,"invited by", inv.get("username","?")+tag,                              V)
    field(t,"expires",      d.get("expires_at"),                                        ER)
    feats = g.get("features",[])
    if feats: field(t,"features",", ".join(f.replace("_"," ").lower() for f in feats), D)
    icon = g.get("icon")
    if icon: field(t,"icon",
                   f"https://cdn.discordapp.com/icons/{g['id']}/{icon}.png",            LK)
    field(t,"invite url",   f"https://discord.gg/{code}",                              LK)
    wrap(t,"server info")
    report_add("discord_server", {**g, "members": d.get("approximate_member_count")})

def scan_discord_user(user_id):
    sep(f"discord user id // {user_id}")
    try:
        uid     = int(user_id)
        ts_ms   = (uid >> 22) + 1420070400000
        created = datetime.fromtimestamp(ts_ms/1000).strftime("%Y-%m-%d %H:%M:%S")
        worker  = (uid & 0x3E0000) >> 17
        process = (uid & 0x1F000)  >> 12
        incr    = uid & 0xFFF
    except:
        pr("err","invalid snowflake id",ER); return

    t = tbl()
    field(t,"user id",        user_id,  A)
    field(t,"account created",created,  V)
    field(t,"worker id",      str(worker),  D)
    field(t,"process id",     str(process), D)
    field(t,"increment",      str(incr),    D)
    field(t,"default avatar", str(uid % 5), D)
    field(t,"avatar url",
          f"https://cdn.discordapp.com/embed/avatars/{uid%5}.png", LK)
    wrap(t,"snowflake decode")

    pr("info","discord does not expose user profiles without oauth2", D)
    pr("info","snowflake decode gives account age — no further passive data available", D)
    pr_link("discord.id",       f"https://discord.id/?prefill={user_id}")
    pr_link("discordlookup",    f"https://discordlookup.com/user/{user_id}")
    pr_link("discord.com/app",  f"https://discord.com/channels/@me")

def _check_platform(name, url, check_fn, profile_url):
    try:
        r = S.get(url, headers={"Accept":"application/json"}, timeout=9)
        if r.ok:
            try:
                detail = check_fn(r.json())
                if detail and isinstance(detail,str):
                    return (name,"found", detail[:55], profile_url)
            except: pass
            if r.status_code==200:
                return (name,"maybe","", profile_url)
        elif r.status_code==404:
            return (name,"miss","","")
        return (name,f"err {r.status_code}","","")
    except:
        return (name,"timeout","","")

def scan_username(username):
    sep(f"username hunt // {username}")

    CHECKS = [
        ("github",     f"https://api.github.com/users/{username}",
         lambda d: d.get("login") and
            f"repos:{d.get('public_repos',0)}  followers:{d.get('followers',0)}  loc:{d.get('location') or '?'}",
         f"https://github.com/{username}"),
        ("gitlab",     f"https://gitlab.com/api/v4/users?username={username}",
         lambda d: d and isinstance(d,list) and len(d)>0 and
            f"name:{d[0].get('name','?')}  id:{d[0].get('id','?')}",
         f"https://gitlab.com/{username}"),
        ("hackernews", f"https://hacker-news.firebaseio.com/v0/user/{username}.json",
         lambda d: d and d!="null" and f"karma:{d.get('karma',0)}",
         f"https://news.ycombinator.com/user?id={username}"),
        ("reddit",     f"https://www.reddit.com/user/{username}/about.json",
         lambda d: d.get("data") and
            f"karma:{d['data'].get('total_karma',0)}  age:{datetime.fromtimestamp(d['data'].get('created_utc',0)).strftime('%Y-%m-%d')}",
         f"https://reddit.com/user/{username}"),
        ("dev.to",     f"https://dev.to/api/users/by_username?url={username}",
         lambda d: d.get("id") and
            f"articles:{d.get('articles_count',0)}  followers:{d.get('followers_count',0)}",
         f"https://dev.to/{username}"),
        ("keybase",    f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={username}",
         lambda d: d.get("them") and len(d["them"])>0 and
            f"id:{d['them'][0].get('id','?')}  proofs:{len(d['them'][0].get('proofs_summary',{}).get('all',[]))}",
         f"https://keybase.io/{username}"),
        ("gravatar",   f"https://en.gravatar.com/{username}.json",
         lambda d: d.get("entry") and
            f"display:{d['entry'][0].get('displayName','?')}",
         f"https://gravatar.com/{username}"),
        ("npm",        f"https://registry.npmjs.org/-/user/org.couchdb.user:{username}",
         lambda d: d.get("name") and f"name:{d.get('name','?')}",
         f"https://www.npmjs.com/~{username}"),
        ("pypi",       f"https://pypi.org/user/{username}/",
         lambda d: True,
         f"https://pypi.org/user/{username}/"),
        ("cashapp",    f"https://cash.app/${username}",
         lambda d: True,
         f"https://cash.app/${username}"),
                      ("youtube",
                      lambda r: "channel exists" if r.status_code == 200 else None,  
                             f"https://www.youtube.com/@{username}",
                     f"https://www.youtube.com/@{username}"),
    ]  

    pr("hunt","running concurrent platform checks...", D)
    results = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(_check_platform,*c): c[0] for c in CHECKS}
        for fut in as_completed(futs):
            results.append(fut.result())

    results.sort(key=lambda x: (0 if x[1]=="found" else 1 if x[1]=="maybe" else 2))

    rt = ctbl([("platform",A,14),("status",None,10),("details",D,44),("url",D)])
    for name,status,detail,url in results:
        if status=="found":
            s = f"[{OK}]✓ found[/{OK}]"
        elif status=="maybe":
            s = f"[{A}]? maybe[/{A}]"
        elif status=="miss":
            s = f"[{D}]– miss[/{D}]"
        else:
            s = f"[{ER}]{status}[/{ER}]"
        rt.add_row(name, s, detail, url[:48] if url else "")
    wrap(rt,"live api checks")

    MANUAL = [
        ("twitch",      f"https://twitch.tv/{username}"),
        ("steam",       f"https://steamcommunity.com/id/{username}"),
        ("medium",      f"https://medium.com/@{username}"),
        ("replit",      f"https://replit.com/@{username}"),
        ("codepen",     f"https://codepen.io/{username}"),
        ("linktree",    f"https://linktr.ee/{username}"),
        ("pastebin",    f"https://pastebin.com/u/{username}"),
        ("soundcloud",  f"https://soundcloud.com/{username}"),
        ("hashnode",    f"https://hashnode.com/@{username}"),
        ("mastodon",    f"https://mastodon.social/@{username}"),
        ("spotify",     f"https://open.spotify.com/user/{username}"),
        ("roblox",      f"https://www.roblox.com/user.aspx?username={username}"),
        ("producthunt", f"https://www.producthunt.com/@{username}"),
        ("behance",     f"https://www.behance.net/{username}"),
        ("dribbble",    f"https://dribbble.com/{username}"),
        ("dockerhub",   f"https://hub.docker.com/u/{username}"),
        ("gitbook",     f"https://{username}.gitbook.io"),
        ("tryhackme",   f"https://tryhackme.com/p/{username}"),
        ("hackthebox",  f"https://app.hackthebox.com/users/search?term={username}"),
    ]
    mt = ctbl([("platform",A,18),("url",LK)])
    for n,u in MANUAL: mt.add_row(n,u)
    wrap(mt,"profile links (verify manually)")

    guesses = [f"{username}@gmail.com",f"{username}@yahoo.com",
               f"{username}@outlook.com",f"{username}@protonmail.com",
               f"{username}@icloud.com",f"contact@{username}.com"]
    console.print(Panel(
        "\n".join(f"[{D}]→[/{D}] [{D}]{e}[/{D}]" for e in guesses),
        title=f"[{A}] email patterns [/{A}]", border_style=D, padding=(0,2)))

def scan_ip(ip):
    sep(f"ip recon // {ip}")

    with spin("querying ip-api.com..."):
        r = get(
            f"http://ip-api.com/json/{ip}"
            "?fields=status,message,country,countryCode,region,regionName,"
            "city,zip,lat,lon,timezone,isp,org,as,asname,query,mobile,proxy,hosting"
        )
    d = r.json()
    if d.get("status")=="fail": pr("err",d.get("message","fail"),ER); return

    t = tbl()
    field(t,"ip",           d.get("query"),                                      A)
    field(t,"country",      f'{d.get("country")} [{d.get("countryCode")}]',      V)
    field(t,"region",       f'{d.get("regionName")} ({d.get("region")})',         V)
    field(t,"city",         d.get("city"),                                        V)
    field(t,"zip",          d.get("zip"),                                         D)
    field(t,"coordinates",  f'{d.get("lat")}, {d.get("lon")}',                   V)
    field(t,"timezone",     d.get("timezone"),                                    D)
    field(t,"isp",          d.get("isp"),                                         V)
    field(t,"org",          d.get("org"),                                         V)
    field(t,"asn",          d.get("as"),                                          D)
    field(t,"as name",      d.get("asname"),                                      D)
    field(t,"mobile",       str(d.get("mobile")),                                 D)
    field(t,"proxy / vpn",  "YES — flagged" if d.get("proxy") else "no",
          ER if d.get("proxy") else D)
    field(t,"hosting / dc", "YES — datacenter" if d.get("hosting") else "no",
          A if d.get("hosting") else D)
    field(t,"maps",         f'https://maps.google.com/?q={d.get("lat")},{d.get("lon")}', LK)
    wrap(t,"geolocation")
    report_add("ip", d)

    # reverse DNS
    try:
        host = socket.gethostbyaddr(d.get("query",""))[0]
        console.print(Panel(f"[{V}]{host}[/{V}]",
                            title=f"[{A}] reverse dns [/{A}]",
                            border_style=D, padding=(0,2)))
    except:
        console.print(Panel(f"[{D}]no reverse dns record[/{D}]",
                            title=f"[{A}] reverse dns [/{A}]",
                            border_style=D, padding=(0,2)))

    # BGP / ASN info
    with spin("querying bgp.he.net..."):
        try:
            rb = get(f"https://bgp.he.net/ip/{d.get('query','')}", timeout=8)
            asn_match = re.findall(r'AS(\d+)', rb.text)
            if asn_match:
                unique_asns = list(dict.fromkeys(asn_match))[:4]
                pr("bgp", f"ASNs from BGP data: {', '.join('AS'+a for a in unique_asns)}", D)
        except: pass

    pr_link("shodan",     f"https://www.shodan.io/host/{d.get('query')}")
    pr_link("abuseipdb",  f"https://www.abuseipdb.com/check/{d.get('query')}")
    pr_link("virustotal", f"https://www.virustotal.com/gui/ip-address/{d.get('query')}")
    pr_link("censys",     f"https://search.censys.io/hosts/{d.get('query')}")
    pr_link("bgp.he.net", f"https://bgp.he.net/ip/{d.get('query')}")

def scan_domain(domain):
    domain = re.sub(r'^https?://','',domain).split("/")[0].strip()
    sep(f"domain recon // {domain}")

    # DNS
    RTYPES = ["A","AAAA","MX","NS","TXT","CNAME","SOA","CAA","PTR"]
    dt = ctbl([("type",A,8),("ttl",D,8),("value",V)])
    with spin("dns records via cloudflare doh..."):
        for rtype in RTYPES:
            try:
                r = S.get(
                    f"https://cloudflare-dns.com/dns-query?name={domain}&type={rtype}",
                    headers={"Accept":"application/dns-json"}, timeout=9)
                for ans in r.json().get("Answer",[]):
                    dt.add_row(rtype, str(ans.get("TTL",0)), ans.get("data","")[:80])
            except: pass
    wrap(dt,"dns records")

    # subdomains via crt.sh
    with spin("ssl cert / subdomain discovery via crt.sh..."):
        try:
            r = get(f"https://crt.sh/?q=%25.{domain}&output=json")
            if r.ok:
                certs = r.json()
                seen  = set()
                ct = ctbl([("subdomain",V,34),("issuer",D,36),("not before",D,12)])
                for c in sorted(certs,key=lambda x: x.get("not_before",""),reverse=True):
                    sub = c.get("name_value","").replace("*.","")
                    for s in sub.split("\n"):
                        s = s.strip()
                        if s and s not in seen:
                            seen.add(s)
                            ct.add_row(s, c.get("issuer_name","?")[:36],
                                       str(c.get("not_before",""))[:10])
                    if len(seen)>=30: break
                wrap(ct, f"subdomains from ssl certs ({len(seen)} unique)")
        except Exception as e:
            pr("ssl",f"crt.sh failed: {e}",ER)

    # Wayback Machine CDX snapshot history
    with spin("wayback machine history..."):
        try:
            r = get(
                f"https://web.archive.org/cdx/search/cdx"
                f"?url={domain}&output=json&limit=10&fl=timestamp,statuscode,mimetype,urlkey"
                f"&collapse=digest&filter=statuscode:200",
                timeout=12
            )
            if r.ok:
                rows = r.json()
                if len(rows)>1:
                    wt = ctbl([("timestamp",D,18),("status",A,8),("type",D,20),("url",V)])
                    for row in rows[1:11]:
                        ts2,sc,mt,uk = row[0],row[1],row[2],row[3]
                        wt.add_row(
                            f"{ts2[:4]}-{ts2[4:6]}-{ts2[6:8]} {ts2[8:10]}:{ts2[10:12]}",
                            sc, mt[:20], uk[:50]
                        )
                    wrap(wt, f"wayback machine snapshots (oldest first)")
                    # first/last seen
                    first = rows[1][0]; last = rows[-1][0]
                    pr("wayback", f"first snapshot: {first[:4]}-{first[4:6]}-{first[6:8]}", D)
                    pr("wayback", f"snapshots available at: https://web.archive.org/web/*/{domain}", D)
        except Exception as e:
            pr("wayback",f"failed: {e}",ER)

    # RDAP WHOIS
    with spin("rdap whois..."):
        try:
            r = get(f"https://rdap.org/domain/{domain}")
            if r.ok:
                rd = r.json()
                wt = tbl()
                field(wt,"ldh name", rd.get("ldhName"), A)
                field(wt,"status",   ", ".join(rd.get("status",[])), D)
                for ev in rd.get("events",[]):
                    act  = ev.get("eventAction","?")
                    date = str(ev.get("eventDate",""))[:10]
                    col  = ER if "expir" in act else A if "registr" in act else D
                    wt.add_row(f"[{D}]{act}[/{D}]",f"[{col}]{date}[/{col}]")
                for ns in rd.get("nameservers",[]):
                    wt.add_row(f"[{D}]nameserver[/{D}]",
                               f"[{V}]{ns.get('ldhName','')}[/{V}]")
                for ent in rd.get("entities",[]):
                    roles = "/".join(ent.get("roles",[]))
                    name  = ""
                    if ent.get("vcardArray") and ent["vcardArray"][1]:
                        fn = next((v for v in ent["vcardArray"][1] if v[0]=="fn"),None)
                        if fn: name = fn[3]
                    if name:
                        wt.add_row(f"[{D}]{roles.upper()}[/{D}]",f"[{V}]{name}[/{V}]")
                wrap(wt,"whois (rdap)")
        except Exception as e:
            pr("rdap",f"failed: {e}",ER)

    # HTTP headers / tech fingerprint
    with spin("http header fingerprint..."):
        try:
            rh = S.head(f"https://{domain}", timeout=10, allow_redirects=True)
            ht = tbl()
            interesting = ["server","x-powered-by","x-generator","via","x-frame-options",
                           "strict-transport-security","content-security-policy",
                           "x-content-type-options","x-cache","cf-ray","x-amz-cf-id"]
            for h in interesting:
                v2 = rh.headers.get(h)
                if v2: field(ht, h, v2[:80], V)
            field(ht,"final url", str(rh.url), LK)
            field(ht,"status",    str(rh.status_code), OK if rh.status_code<400 else ER)
            wrap(ht,"http headers")
        except: pass

    pr_link("virustotal",    f"https://www.virustotal.com/gui/domain/{domain}")
    pr_link("shodan",        f"https://www.shodan.io/search?query=hostname%3A{domain}")
    pr_link("archive.org",   f"https://web.archive.org/web/*/{domain}")
    pr_link("securitytrails",f"https://securitytrails.com/domain/{domain}/dns")
    pr_link("censys",        f"https://search.censys.io/search?resource=hosts&q={domain}")
    pr_link("dnsdumpster",   f"https://dnsdumpster.com")

def scan_npm(package):
    sep(f"npm // {package}")

    with spin("querying registry.npmjs.org..."):
        r = get(f"https://registry.npmjs.org/{package}")
    if r.status_code==404: pr("err","package not found",ER); return

    d      = r.json()
    latest = d.get("dist-tags",{}).get("latest","?")
    lv     = d.get("versions",{}).get(latest,{})
    tm     = d.get("time",{})

    t = tbl()
    field(t,"name",         d.get("name"),                            A)
    field(t,"description",  d.get("description"),                     V)
    field(t,"latest",       latest,                                   OK)
    field(t,"license",      lv.get("license") or d.get("license"),    V)
    auth = d.get("author")
    if isinstance(auth,dict):
        field(t,"author", f'{auth.get("name","?")} <{auth.get("email","?")}>', V)
    elif auth: field(t,"author", str(auth), V)
    maint = d.get("maintainers",[])
    if maint: field(t,"maintainers",
                    ", ".join(f'{m.get("name","?")} <{m.get("email","?")}>' for m in maint), V)
    repo = lv.get("repository",{})
    if isinstance(repo,dict): field(t,"repo", repo.get("url","").replace("git+",""), LK)
    field(t,"homepage",     lv.get("homepage"),                       LK)
    field(t,"versions",     str(len(d.get("versions",{}))),           D)
    field(t,"first pub",    str(tm.get("created",""))[:10],           D)
    field(t,"last mod",     str(tm.get("modified",""))[:10],          D)
    deps = lv.get("dependencies",{})
    if deps: field(t,"dependencies", str(len(deps)),                  D)
    kw = d.get("keywords",[])
    if kw: field(t,"keywords", ", ".join(kw[:10]),                    D)
    field(t,"page",         f"https://www.npmjs.com/package/{package}",LK)
    wrap(t,"package info")

    with spin("download stats..."):
        rm = get(f"https://api.npmjs.org/downloads/point/last-month/{package}")
        ry = get(f"https://api.npmjs.org/downloads/point/last-year/{package}")
    st = tbl()
    if rm.ok: field(st,"downloads / 30d",  f'{rm.json().get("downloads",0):,}', A)
    if ry.ok: field(st,"downloads / year", f'{ry.json().get("downloads",0):,}', A)
    wrap(st,"download stats")

    versions = list(d.get("versions",{}).keys())[-15:]
    vt = ctbl([("version",A,20),("date",D)])
    for v in reversed(versions): vt.add_row(v, str(tm.get(v,""))[:10])
    wrap(vt,"recent versions")

def scan_pypi(package):
    sep(f"pypi // {package}")

    with spin("querying pypi.org..."):
        r = get(f"https://pypi.org/pypi/{package}/json")
    if r.status_code==404: pr("err","package not found",ER); return

    d    = r.json()
    info = d.get("info",{})
    urls = d.get("urls",[])

    t = tbl()
    field(t,"name",         info.get("name"),           A)
    field(t,"version",      info.get("version"),        OK)
    field(t,"summary",      info.get("summary"),        V)
    field(t,"author",       info.get("author"),         V)
    field(t,"author email", info.get("author_email"),   A)
    field(t,"maintainer",   info.get("maintainer"),     V)
    field(t,"license",      info.get("license"),        D)
    field(t,"home page",    info.get("home_page"),      LK)
    field(t,"project urls", str(info.get("project_urls",{})), D)
    field(t,"requires py",  info.get("requires_python"),D)
    kw = info.get("keywords","")
    if kw: field(t,"keywords", kw[:80], D)
    for c in info.get("classifiers",[]):
        if "Status ::"   in c: field(t,"status",   c.split(" :: ")[-1], A)
        if "Audience ::" in c: field(t,"audience", c.split(" :: ")[-1], D)
    req = info.get("requires_dist") or []
    if req: field(t,"requires", ", ".join(req[:6]), D)
    if urls:
        u = urls[0]
        field(t,"filename",  u.get("filename"),              D)
        field(t,"size",      f'{u.get("size",0):,} bytes',   D)
        field(t,"uploaded",  str(u.get("upload_time",""))[:10], D)
    field(t,"pypi page",    f"https://pypi.org/project/{info.get('name')}/", LK)
    wrap(t,"package info")

    releases = list(d.get("releases",{}).keys())
    if releases:
        vt = ctbl([("version",A,22),("files",D)])
        for v in reversed(releases[-15:]): vt.add_row(v, str(len(d["releases"].get(v,[]))))
        wrap(vt, f"version history ({len(releases)} total)")

CC = {
    "+1":"US/Canada","+7":"Russia/Kazakhstan","+20":"Egypt","+27":"South Africa",
    "+30":"Greece","+31":"Netherlands","+32":"Belgium","+33":"France","+34":"Spain",
    "+36":"Hungary","+39":"Italy","+40":"Romania","+41":"Switzerland","+43":"Austria",
    "+44":"UK","+45":"Denmark","+46":"Sweden","+47":"Norway","+48":"Poland","+49":"Germany",
    "+51":"Peru","+52":"Mexico","+54":"Argentina","+55":"Brazil","+56":"Chile",
    "+57":"Colombia","+60":"Malaysia","+61":"Australia","+62":"Indonesia",
    "+63":"Philippines","+64":"New Zealand","+65":"Singapore","+66":"Thailand",
    "+81":"Japan","+82":"South Korea","+84":"Vietnam","+86":"China","+90":"Turkey",
    "+91":"India","+92":"Pakistan","+94":"Sri Lanka","+98":"Iran",
    "+212":"Morocco","+213":"Algeria","+216":"Tunisia","+234":"Nigeria",
    "+254":"Kenya","+380":"Ukraine","+966":"Saudi Arabia","+971":"UAE",
    "+972":"Israel","+995":"Georgia","+998":"Uzbekistan","+593":"Ecuador",
    "+502":"Guatemala","+503":"El Salvador","+504":"Honduras","+505":"Nicaragua",
}

def scan_phone(number):
    clean = re.sub(r"[\s\-\(\)\.]","",number)
    if not clean.startswith("+"): clean="+"+re.sub(r"\D","",clean)
    sep(f"phone recon // {clean}")

    t = tbl()
    field(t,"number",clean,A)
    country,dial="Unknown","?"
    for code in sorted(CC.keys(),key=len,reverse=True):
        if clean.startswith(code):
            country,dial=CC[code],code; break
    field(t,"country code",dial,V)
    field(t,"country",     country,V)
    digits = re.sub(r"\D","",clean)
    field(t,"digits",      str(len(digits)),D)
    field(t,"e.164",       clean,D)
    field(t,"national",    digits[len(dial.replace("+","")):] if dial!="?" else digits, D)
    wrap(t,"number analysis")

    lt = ctbl([("database",A,22),("url",LK)])
    for name,url in [
        ("shouldianswer",  f"https://www.shouldianswer.net/phone-number/{digits}"),
        ("800notes",       f"https://800notes.com/Phone.aspx/{digits}"),
        ("spamcalls",      f"https://spamcalls.net/en/search?query={clean}"),
        ("whocalledus",    f"https://whocalledus.com/phone/{clean.replace('+','-')}"),
        ("calleridtest",   f"https://www.calleridtest.com/phone-number/{digits}"),
        ("truecaller web", f"https://www.truecaller.com/search/us/{digits}"),
    ]:
        lt.add_row(name,url)
    wrap(lt,"spam & report databases")
    pr("note","full carrier/owner id requires paid api (twilio / numverify)",D)

def scan_telegram(handle):
    clean = handle.lstrip("@")
    sep(f"telegram // @{clean}")

    with spin(f"fetching t.me/{clean}..."):
        try:
            r    = S.get(f"https://t.me/{clean}", timeout=14)
            html = r.text
        except Exception as e:
            pr("err",f"request failed: {e}",ER); return

    t = tbl()
    for pat,label,col in [
        (r'<meta property="og:title" content="([^"]+)"',       "title",       V),
        (r'<meta property="og:description" content="([^"]+)"', "description", V),
        (r'<meta property="og:image" content="([^"]+)"',       "avatar url",  LK),
    ]:
        m = re.search(pat,html)
        if m: field(t,label,m.group(1)[:120],col)

    mem = re.search(r'([\d\s,]+)\s*(members|subscribers|online)',html,re.IGNORECASE)
    if mem: field(t,"members",mem.group(1).strip()+" "+mem.group(2),A)
    is_chan = "tgme_page_extra" in html
    field(t,"type",   "channel / group" if is_chan else "user / bot",V)
    field(t,"status", "public" if "tgme_page" in html else "private / not found",
          OK if "tgme_page" in html else ER)
    field(t,"url",    f"https://t.me/{clean}",LK)
    wrap(t,"profile")

    # try preview endpoint for extra data
    with spin("trying telegram preview api..."):
        try:
            rp = get(f"https://t.me/s/{clean}", timeout=10)
            if rp.ok:
                post_count = len(re.findall(r'tgme_widget_message_wrap',rp.text))
                if post_count:
                    pr("telegram",f"visible posts in preview: ~{post_count}",D)
        except: pass

    pr_link("tgstat",     f"https://tgstat.com/en/search?q={clean}")
    pr_link("telemetrio", f"https://telemetrio.com/search/{clean}")
    pr_link("google",     f"https://google.com/search?q=site:t.me+{clean}")

def scan_email(email):
    sep(f"email recon // {email}")
    parts  = email.split("@")
    user   = parts[0] if len(parts)==2 else email
    domain = parts[1] if len(parts)==2 else ""
    md5    = hashlib.md5(email.strip().lower().encode()).hexdigest()
    sha1   = hashlib.sha1(email.strip().lower().encode()).hexdigest()

    t = tbl()
    field(t,"email",    email, A)
    field(t,"username", user,  V)
    field(t,"domain",   domain,V)
    field(t,"md5",      md5,   D)
    field(t,"sha1",     sha1,  D)
    field(t,"gravatar", f"https://www.gravatar.com/avatar/{md5}?d=404",LK)
    wrap(t,"analysis")

    # gravatar
    with spin("checking gravatar..."):
        try:
            rg = get(f"https://en.gravatar.com/{md5}.json")
            if rg.ok:
                entry = rg.json().get("entry",[{}])[0]
                gt    = tbl()
                field(gt,"display name", entry.get("displayName"),       V)
                field(gt,"username",     entry.get("preferredUsername"),  A)
                field(gt,"profile url",  entry.get("profileUrl"),        LK)
                field(gt,"location",     entry.get("currentLocation"),    V)
                field(gt,"about me",     entry.get("aboutMe","")[:80],   D)
                for acc in entry.get("accounts",[]):
                    field(gt,acc.get("shortname","?"),acc.get("url","?"),LK)
                wrap(gt,"gravatar profile — found")
                report_add("email_gravatar", entry)
            else:
                pr("gravatar","no profile found",D)
        except: pr("gravatar","check failed",ER)

    # MX
    if domain:
        with spin(f"mx records for {domain}..."):
            try:
                r2 = S.get(
                    f"https://cloudflare-dns.com/dns-query?name={domain}&type=MX",
                    headers={"Accept":"application/dns-json"}, timeout=9)
                answers = r2.json().get("Answer",[])
                if answers:
                    mx = ctbl([("priority",A,10),("mx host",V)])
                    for ans in answers:
                        p = ans.get("data","").split()
                        mx.add_row(p[0] if len(p)>=2 else "?",
                                   p[1] if len(p)>=2 else ans.get("data","?"))
                    wrap(mx,"mx records")
            except: pass

    lt = ctbl([("service",A,20),("url",LK)])
    for n,u in [
        ("haveibeenpwned", f"https://haveibeenpwned.com/account/{email}"),
        ("dehashed",       f"https://www.dehashed.com/search?query={email}"),
        ("leakcheck",      f"https://leakcheck.io/search/{email}"),
        ("hunter.io",      f"https://hunter.io/email-verifier/{email}"),
        ("emailrep",       f"https://emailrep.io/{email}"),
        ("snov.io",        f"https://app.snov.io/email-finder?email={email}"),
    ]:
        lt.add_row(n,u)
    wrap(lt,"breach & reputation links")

def scan_hackernews(username):
    sep(f"hackernews // {username}")

    with spin("querying hn api..."):
        r = get(f"https://hacker-news.firebaseio.com/v0/user/{username}.json")
    if not r.ok or r.text=="null": pr("err","user not found",ER); return

    d = r.json()
    t = tbl()
    field(t,"username", d.get("id"),                                       A)
    field(t,"created",  datetime.fromtimestamp(d.get("created",0)).strftime("%Y-%m-%d"), D)
    field(t,"karma",    str(d.get("karma",0)),                             A)
    field(t,"about",    re.sub(r'<[^>]+>','',d.get("about",""))[:120],     V)
    field(t,"profile",  f"https://news.ycombinator.com/user?id={username}",LK)
    wrap(t,"hn profile")

    submitted = d.get("submitted",[])[:12]
    if submitted:
        with spin("fetching submissions..."):
            it = ctbl([("type",A,8),("date",D,12),("title",V,45),("pts",D,5),("url",D)])
            for item_id in submitted:
                try:
                    ri = get(f"https://hacker-news.firebaseio.com/v0/item/{item_id}.json")
                    if ri.ok and ri.text!="null":
                        item = ri.json()
                        it.add_row(
                            item.get("type","?"),
                            datetime.fromtimestamp(item.get("time",0)).strftime("%Y-%m-%d"),
                            (item.get("title") or item.get("text","")[:40] or "?")[:45],
                            str(item.get("score",0)),
                            (item.get("url") or
                             f"https://news.ycombinator.com/item?id={item_id}")[:50]
                        )
                except: pass
                time.sleep(0.1)
        wrap(it,"recent submissions")

def scan_reddit(username):
    sep(f"reddit // u/{username}")

    with spin("querying reddit api..."):
        r = get(f"https://www.reddit.com/user/{username}/about.json",
                headers={"Accept":"application/json"})
    if r.status_code==404: pr("err","user not found or suspended",ER); return
    if not r.ok: pr("err",f"http {r.status_code}",ER); return

    d = r.json().get("data",{})
    t = tbl()
    field(t,"username",      d.get("name"),                                      A)
    field(t,"id",            d.get("id"),                                         D)
    field(t,"created",       datetime.fromtimestamp(d.get("created_utc",0)).strftime("%Y-%m-%d"), D)
    field(t,"total karma",   f'{d.get("total_karma",0):,}',                       A)
    field(t,"post karma",    f'{d.get("link_karma",0):,}',                        V)
    field(t,"comment karma", f'{d.get("comment_karma",0):,}',                     V)
    field(t,"award karma",   f'{d.get("awardee_karma",0):,}',                     D)
    field(t,"gold",          str(d.get("is_gold",False)),                         D)
    field(t,"moderator",     str(d.get("is_mod",False)),                          D)
    field(t,"verified email",str(d.get("has_verified_email",False)),              D)
    field(t,"nsfw",          str(d.get("over_18",False)),
          ER if d.get("over_18") else D)
    field(t,"icon",          d.get("icon_img","").split("?")[0],                  D)
    field(t,"profile",       f"https://reddit.com/u/{d.get('name')}",            LK)
    wrap(t,"reddit profile")
    report_add("reddit", d)

    # posts
    with spin("fetching recent posts..."):
        rp = get(f"https://www.reddit.com/user/{username}/submitted.json?limit=10",
                 headers={"Accept":"application/json"})
    if rp.ok:
        posts = rp.json().get("data",{}).get("children",[])
        if posts:
            pt = ctbl([("date",D,12),("subreddit",A,20),("score",V,7),("title",V)])
            for post in posts:
                pd2 = post.get("data",{})
                pt.add_row(
                    datetime.fromtimestamp(pd2.get("created_utc",0)).strftime("%Y-%m-%d"),
                    "r/"+pd2.get("subreddit","?"),
                    str(pd2.get("score",0)),
                    (pd2.get("title","?"))[:55]
                )
            wrap(pt,"recent posts")

    # comments
    with spin("fetching recent comments..."):
        rc = get(f"https://www.reddit.com/user/{username}/comments.json?limit=6",
                 headers={"Accept":"application/json"})
    if rc.ok:
        comments = rc.json().get("data",{}).get("children",[])
        if comments:
            cmt = ctbl([("date",D,12),("subreddit",A,20),("score",V,7),("body",D)])
            for c in comments:
                cd = c.get("data",{})
                cmt.add_row(
                    datetime.fromtimestamp(cd.get("created_utc",0)).strftime("%Y-%m-%d"),
                    "r/"+cd.get("subreddit","?"),
                    str(cd.get("score",0)),
                    (cd.get("body","?"))[:55].replace("\n"," ")
                )
            wrap(cmt,"recent comments")

def scan_keybase(username):
    sep(f"keybase // {username}")

    with spin("querying keybase api..."):
        r = get(f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={username}")
    if not r.ok: pr("err",f"http {r.status_code}",ER); return

    d    = r.json()
    them = d.get("them",[])
    if not them: pr("err","user not found",ER); return

    u    = them[0]
    basics = u.get("basics",{})
    prof   = u.get("profile",{})
    pics   = u.get("pictures",{})

    t = tbl()
    field(t,"username",    basics.get("username"),             A)
    field(t,"id",          u.get("id"),                        D)
    field(t,"uid",         basics.get("uid"),                  D)
    field(t,"full name",   prof.get("full_name"),               V)
    field(t,"location",    prof.get("location"),                V)
    field(t,"bio",         prof.get("bio","")[:100],            V)
    field(t,"created",     str(basics.get("ctime",""))[:10],    D)
    field(t,"profile",     f"https://keybase.io/{username}",    LK)
    primary_pic = (pics.get("primary") or {}).get("url","")
    if primary_pic: field(t,"avatar",primary_pic,D)
    wrap(t,"keybase profile")

    # proof chain
    proofs = u.get("proofs_summary",{}).get("all",[])
    if proofs:
        pt = ctbl([("type",A,16),("username/url",V,28),("state",D,8),("url",LK)])
        for p in proofs:
            state = "✓" if p.get("proof_type") else "?"
            pt.add_row(
                p.get("proof_type","?"),
                p.get("nametag","?"),
                str(p.get("state","")),
                p.get("proof_url","")[:50]
            )
        wrap(pt, f"verified identity proofs ({len(proofs)})")
        report_add("keybase_proofs", proofs)

    # PGP keys
    pgp_keys = u.get("public_keys",{}).get("pgp_public_keys",[])
    if pgp_keys:
        pr("keybase",f"pgp public keys: {len(pgp_keys)} found",A)
        for k in pgp_keys[:2]:
            pr("keybase",f"  fingerprint: {k.get('fingerprint','?')}",D)

def scan_devto(username):
    sep(f"dev.to // {username}")

    with spin("querying dev.to api..."):
        r = get(f"https://dev.to/api/users/by_username?url={username}")
    if not r.ok: pr("err",f"user not found (http {r.status_code})",ER); return

    d = r.json()
    t = tbl()
    field(t,"username",        d.get("username"),                A)
    field(t,"name",            d.get("name"),                    V)
    field(t,"summary",         d.get("summary","")[:100],        V)
    field(t,"location",        d.get("location"),                V)
    field(t,"id",              str(d.get("id")),                  D)
    field(t,"joined",          str(d.get("joined_at",""))[:10],   D)
    field(t,"articles",        str(d.get("articles_count",0)),    A)
    field(t,"comments",        str(d.get("comments_count",0)),    D)
    field(t,"followers",       str(d.get("followers_count",0)),   A)
    field(t,"github",          d.get("github_username"),          LK)
    field(t,"twitter",         d.get("twitter_username"),         LK)
    field(t,"website",         d.get("website_url"),              LK)
    field(t,"profile",         f"https://dev.to/{username}",      LK)
    wrap(t,"dev.to profile")

    with spin("fetching articles..."):
        ra = get(f"https://dev.to/api/articles?username={username}&per_page=8")
    if ra.ok and ra.json():
        at = ctbl([("date",D,12),("❤",A,6),("💬",D,6),("title",V)])
        for a in ra.json():
            at.add_row(
                str(a.get("published_at",""))[:10],
                str(a.get("positive_reactions_count",0)),
                str(a.get("comments_count",0)),
                (a.get("title","?"))[:55]
            )
        wrap(at,"articles")
MODULES = {
    "1":  ("github user",         scan_github,         "username"),
    "2":  ("discord server",      scan_discord_server, "invite code / discord.gg/xxx"),
    "3":  ("discord user id",     scan_discord_user,   "snowflake user id"),
    "4":  ("username hunt",       scan_username,       "username  (concurrent, 10+ platforms)"),
    "5":  ("ip geolocation",      scan_ip,             "ip address"),
    "6":  ("domain recon",        scan_domain,         "domain  (dns + subdomains + wayback + headers)"),
    "7":  ("npm package",         scan_npm,            "package name"),
    "8":  ("pypi package",        scan_pypi,           "package name"),
    "9":  ("phone analyzer",      scan_phone,          "+international format"),
    "10": ("telegram",            scan_telegram,       "@username or channel"),
    "11": ("email osint",         scan_email,          "email address"),
    "12": ("hackernews user",     scan_hackernews,     "hn username"),
    "13": ("reddit user",         scan_reddit,         "username  (posts + comments)"),
    "14": ("keybase proofs",      scan_keybase,        "keybase username  (identity chain)"),
    "15": ("dev.to profile",      scan_devto,          "dev.to username"),
}

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("module", nargs="?")
    parser.add_argument("target", nargs="?")
    parser.add_argument("--json", metavar="FILE",
                        help="save all results to json file after scan")
    args, _ = parser.parse_known_args()
    json_out = args.json

    if args.module and args.target:
        for k,(name,fn,_) in MODULES.items():
            if args.module.lower() in name.replace(" ",""):
                fn(args.target)
                if json_out: save_report(json_out)
                return
        print(f"unknown module: {args.module}")
        return

    while True:
        try:
            banner()
            t = Table(box=box.SIMPLE, show_header=True,
                      header_style=f"bold {D}",
                      border_style=D, show_edge=False, padding=(0,3))
            t.add_column("#",      style=A, width=4,  no_wrap=True)
            t.add_column("module", style=V, width=24, no_wrap=True)
            t.add_column("target hint", style=D)
            for k,(name,_,hint) in MODULES.items():
                t.add_row(k,name,hint)
            console.print(Align.center(t))
            console.print(Align.center(f"[{D}]  [0] exit   [s] save report[/{D}]"))
            console.print()
            choice = console.input(f"[{D}]  helix » [/{D}]").strip()

            if choice=="0":
                console.print(f"\n[{D}]  shutting down.[/{D}]\n"); break

            if choice=="s":
                path = console.input(f"[{D}]  save to (e.g. report.json) » [/{D}]").strip()
                if path: save_report(path)
                continue

            if choice not in MODULES:
                pr("err","invalid selection",ER); time.sleep(1); continue

            name,fn,hint = MODULES[choice]
            console.print(f"\n  [{D}]{hint}[/{D}]")
            target = console.input(f"[{D}]  target » [/{D}]").strip()
            if not target:
                pr("err","no target",ER); time.sleep(1); continue

            print()
            fn(target)
            print()

            if json_out: save_report(json_out)
            console.input(f"[{D}]  [ enter to return ][/{D}]")

        except KeyboardInterrupt:
            console.print(f"\n[{D}]  interrupted.[/{D}]\n"); break
        except requests.exceptions.ConnectionError:
            pr("err","connection failed",ER); time.sleep(2)
        except requests.exceptions.Timeout:
            pr("err","timed out",ER); time.sleep(1)
        except Exception as e:
            pr("err",str(e),ER); time.sleep(1)

if __name__=="__main__":
    main()