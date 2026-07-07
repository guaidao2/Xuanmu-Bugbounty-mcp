"""从 FingerprintHub 导入的精选指纹库

来源: https://github.com/0x727/FingerprintHub
格式转换: 多关键词 AND / Favicon哈希 / Header匹配
条目数: ~120 条精选高价值指纹
"""

HUB_FINGERPRINTS = [
    # ===================== OA / 办公（高价值） =====================
    {"name":"泛微 OA (Weaver)","cats":[4],"method":"keyword_and","location":"body","keywords":["/wui/theme/"],"confidence":"高"},
    {"name":"泛微 E-Office","cats":[4],"method":"keyword_and","location":"body","keywords":["/eoffice/","泛微"],"confidence":"高"},
    {"name":"泛微 E-Mobile","cats":[4],"method":"keyword_and","location":"body","keywords":["weaver","e-mobile"],"confidence":"高"},
    {"name":"致远 OA (Seeyon)","cats":[4],"method":"keyword_and","location":"body","keywords":["/seeyon/"],"confidence":"高"},
    {"name":"致远 M1 Server","cats":[4],"method":"keyword_and","location":"title","keywords":["M1-Server"],"confidence":"高"},
    {"name":"通达 OA (Tongda)","cats":[4],"method":"keyword_and","location":"body","keywords":["Office Anywhere","/images/tongda.ico"],"confidence":"高"},
    {"name":"蓝凌 OA (Landray)","cats":[4],"method":"keyword_and","location":"body","keywords":["蓝凌软件","sys/ui/extend/"],"confidence":"高"},
    {"name":"万户 ezOFFICE","cats":[4],"method":"favicon","favicon_hash":-1827521324,"confidence":"高"},
    {"name":"用友 NC / U8","cats":[5],"method":"keyword_and","location":"body","keywords":["用友","/web/"],"confidence":"中"},
    {"name":"金蝶云星空","cats":[5],"method":"keyword_and","location":"body","keywords":["HTML5/content/themes/kdcss.min.css"],"confidence":"高"},
    {"name":"金蝶 EAS","cats":[5],"method":"keyword_and","location":"body","keywords":["eassso","portalClientHelper.jsp"],"confidence":"高"},
    {"name":"金和协同管理平台","cats":[4],"method":"keyword_and","location":"body","keywords":["Jhsoft.Web.login","PassWord.aspx"],"confidence":"高"},
    {"name":"红帆 iOffice","cats":[4],"method":"keyword_and","location":"title","keywords":["iOffice.net"],"confidence":"高"},
    {"name":"78OA","cats":[4],"method":"keyword_and","location":"body","keywords":["78OA办公系统","/resource/javascript/system/runtime.min.js"],"confidence":"高"},
    {"name":"信呼 OA","cats":[4],"method":"favicon","favicon_hash":1652488516,"confidence":"高"},
    {"name":"启明星辰 天清汉马","cats":[9],"method":"keyword_and","location":"body","keywords":["天清汉马USG"],"confidence":"高"},

    # ===================== CMS / 博客 =====================
    {"name":"74CMS","cats":[1],"method":"keyword_and","location":"body","keywords":["content=\"74cms.com\"","selectjobscategory"],"confidence":"高"},
    {"name":"PbootCMS","cats":[1],"method":"keyword_and","location":"header","keywords":["PbootCMS"],"confidence":"高"},
    {"name":"DedeCMS","cats":[1],"method":"keyword_and","location":"body","keywords":["DedeCMS","Power by DedeCms"],"confidence":"高"},
    {"name":"蝉知企业门户 (ChanZhi)","cats":[1],"method":"keyword_and","location":"body","keywords":["chanzhi","chanzhi.js"],"confidence":"高"},
    {"name":"FineCMS","cats":[1],"method":"keyword_and","location":"body","keywords":["content=\"FineCMS"],"confidence":"高"},
    {"name":"MetInfo","cats":[1],"method":"keyword_and","location":"body","keywords":["MetInfo","metinfo"],"confidence":"高"},
    {"name":"SiteServer CMS","cats":[1],"method":"keyword_and","location":"body","keywords":["siteserver","SiteServer CMS"],"confidence":"高"},
    {"name":"CmsEasy","cats":[1],"method":"keyword_and","location":"body","keywords":["CmsEasy","/js/cms/"],"confidence":"中"},
    {"name":"YzmCMS","cats":[1],"method":"keyword_and","location":"body","keywords":["YzmCMS","yzmcms"],"confidence":"中"},
    {"name":"Z-Blog","cats":[3],"method":"keyword_and","location":"body","keywords":["Z-Blog","zb_users/"],"confidence":"高"},
    {"name":"EmpireCMS","cats":[1],"method":"keyword_and","location":"body","keywords":["EmpireCMS","empirecms"],"confidence":"高"},
    {"name":"PHPCMS","cats":[1],"method":"keyword_and","location":"body","keywords":["PHPCMS","/phpcms/"],"confidence":"中"},
    {"name":"ECShop","cats":[1],"method":"keyword_and","location":"body","keywords":["ECShop","ecshop"],"confidence":"高"},

    # ===================== 论坛 / 社区 =====================
    {"name":"Discuz!","cats":[2],"method":"keyword_and","location":"body","keywords":["Discuz!","comsenz"],"confidence":"高"},
    {"name":"PHPWind","cats":[2],"method":"keyword_and","location":"body","keywords":["PHPWind","phpwind"],"confidence":"高"},

    # ===================== DevOps / 监控 =====================
    {"name":"xxl-job","cats":[20],"method":"keyword_and","location":"body","keywords":["xxl-job","/static/adminlte/"],"confidence":"高"},
    {"name":"Grafana","cats":[12],"method":"keyword_and","location":"title","keywords":["Grafana"],"confidence":"高"},
    {"name":"Kibana","cats":[12],"method":"keyword_and","location":"title","keywords":["Kibana"],"confidence":"高"},
    {"name":"Jenkins","cats":[20],"method":"keyword_and","location":"body","keywords":["Jenkins","/jenkins/"],"confidence":"高"},
    {"name":"Nexus Repository","cats":[20],"method":"keyword_and","location":"title","keywords":["Nexus Repository Manager"],"confidence":"高"},
    {"name":"Apache Airflow","cats":[20],"method":"keyword_and","location":"title","keywords":["Airflow - Login"],"confidence":"高"},
    {"name":"Swagger UI","cats":[20],"method":"keyword_and","location":"body","keywords":["swagger-ui","Swagger UI"],"confidence":"高"},
    {"name":"Docker Registry","cats":[20],"method":"score","signals":[{"hdr":"Docker-Distribution-Api-Version","pat":".+","w":80}],"confidence":"高"},
    {"name":"Harbor","cats":[20],"method":"keyword_and","location":"body","keywords":["Harbor","harbor-portal"],"confidence":"高"},
    {"name":"JumpServer","cats":[9],"method":"keyword_and","location":"body","keywords":["JumpServer","jumpserver"],"confidence":"高"},
    {"name":"Zabbix","cats":[12],"method":"keyword_and","location":"body","keywords":["Zabbix","zabbix.php"],"confidence":"高"},
    {"name":"Prometheus","cats":[12],"method":"keyword_and","location":"title","keywords":["Prometheus"],"confidence":"中"},

    # ===================== 网络设备 =====================
    {"name":"深信服 SSL VPN","cats":[14],"method":"keyword_and","location":"body","keywords":["/por/login_psw.csp"],"confidence":"高"},
    {"name":"深信服上网行为管理","cats":[11],"method":"keyword_and","location":"body","keywords":["utccjfaewjb","function(str, key)"],"confidence":"高"},
    {"name":"深信服防火墙","cats":[9],"method":"keyword_and","location":"body","keywords":["Redirect to...","/LogInOut.php"],"confidence":"高"},
    {"name":"天融信 VPN","cats":[14],"method":"keyword_and","location":"header","keywords":["topsecsvportalname"],"confidence":"高"},
    {"name":"天融信防火墙","cats":[9],"method":"keyword_and","location":"body","keywords":["TOPSEC","image/aaa.png"],"confidence":"高"},
    {"name":"网康互联网控制网关","cats":[11],"method":"keyword_and","location":"body","keywords":["网康科技","互联网控制网关"],"confidence":"高"},
    {"name":"网康下一代防火墙","cats":[9],"method":"keyword_and","location":"body","keywords":["网康下一代防火墙","/images/dashboard/dashboard.png"],"confidence":"高"},
    {"name":"锐捷 NBR 路由器","cats":[11],"method":"keyword_and","location":"body","keywords":["锐捷网络","ruijie"],"confidence":"中"},
    {"name":"锐捷 SSL VPN","cats":[14],"method":"favicon","favicon_hash":-1525950034,"confidence":"高"},
    {"name":"华为防火墙","cats":[9],"method":"keyword_and","location":"body","keywords":["Huawei","simple/style/default/image/login.png"],"confidence":"中"},
    {"name":"H3C 设备","cats":[11],"method":"keyword_and","location":"body","keywords":["webui/js/jquerylib/jquery-1.7.2.min.js"],"confidence":"中"},
    {"name":"H3C SecPath 堡垒机","cats":[9],"method":"favicon","favicon_hash":1776863739,"confidence":"高"},
    {"name":"Cisco SSLVPN","cats":[14],"method":"keyword_and","location":"body","keywords":["/+CSCOE+/logon.html"],"confidence":"高"},
    {"name":"飞鱼星路由器","cats":[11],"method":"keyword_and","location":"body","keywords":["css/R1Login.css","飞鱼星"],"confidence":"中"},
    {"name":"网御 VPN","cats":[14],"method":"keyword_and","location":"body","keywords":["/vpn/common/js/leadsec.js"],"confidence":"高"},
    {"name":"齐治堡垒机","cats":[9],"method":"keyword_and","location":"body","keywords":["login.php","logo-icon-ico72.png","fp_download"],"confidence":"高"},
    {"name":"Hillstone 防火墙","cats":[9],"method":"keyword_and","location":"body","keywords":["Hillstone","/image/login.jpg"],"confidence":"高"},
    {"name":"山石网科","cats":[9],"method":"keyword_and","location":"body","keywords":["Hillstone","山石"],"confidence":"中"},

    # ===================== 堡垒机 / VPN / 远程 =====================
    {"name":"Teleport 堡垒机","cats":[9],"method":"keyword_and","location":"body","keywords":["teleport.js","login-type-oath"],"confidence":"高"},
    {"name":"齐治堡垒机 (Shterm)","cats":[9],"method":"keyword_and","location":"body","keywords":["login.php","fp_download"],"confidence":"高"},
    {"name":"天玥运维安全网关","cats":[9],"method":"keyword_and","location":"body","keywords":["天玥运维安全网关","css/fw/full.css"],"confidence":"高"},
    {"name":"IP-guard","cats":[9],"method":"keyword_and","location":"body","keywords":["IP-guard","sign/login"],"confidence":"高"},
    {"name":"向日葵 (SunLogin)","cats":[14],"method":"keyword_and","location":"body","keywords":['{"success":false,"msg":"Verification failure"}'],"confidence":"高"},
    {"name":"亿赛通 DLP","cats":[9],"method":"keyword_and","location":"body","keywords":["CDGServer3","welcomebg.jpg"],"confidence":"高"},

    # ===================== 邮件系统 =====================
    {"name":"Coremail","cats":[13],"method":"keyword_and","location":"body","keywords":["coremail/common"],"confidence":"高"},
    {"name":"TurboMail","cats":[13],"method":"keyword_and","location":"body","keywords":["TurboMail","mailmain?type=login"],"confidence":"高"},
    {"name":"Richmail","cats":[13],"method":"keyword_and","location":"body","keywords":["richmail.config.js","RichMail"],"confidence":"高"},
    {"name":"35企业邮箱","cats":[13],"method":"favicon","favicon_hash":1676919780,"confidence":"中"},
    {"name":"263企业邮箱","cats":[13],"method":"keyword_and","location":"body","keywords":["net263.wm.custom_login.homepage_init"],"confidence":"高"},
    {"name":"Coremail XT","cats":[13],"method":"keyword_and","location":"body","keywords":["coremail/common","/coremail/"],"confidence":"高"},
    {"name":"网易企业邮箱","cats":[13],"method":"keyword_and","location":"body","keywords":["网易企业邮箱","qiye.163.com"],"confidence":"中"},
    {"name":"腾讯企业邮箱","cats":[13],"method":"keyword_and","location":"body","keywords":["/cgi-bin/loginpage","exmail.qq.com"],"confidence":"中"},

    # ===================== 视频监控 / IoT =====================
    {"name":"海康威视综合安防","cats":[17],"method":"keyword_and","location":"title","keywords":["综合安防管理平台"],"confidence":"高"},
    {"name":"海康威视 iVMS","cats":[17],"method":"keyword_and","location":"body","keywords":["iVMS-","/portal/"],"confidence":"高"},
    {"name":"大华 DSS","cats":[17],"method":"keyword_and","location":"body","keywords":["DSS","/admin"],"confidence":"中"},
    {"name":"大华视频监控","cats":[17],"method":"keyword_and","location":"body","keywords":["DahuaTech","Dahua"],"confidence":"中"},
    {"name":"NUUO 摄像头","cats":[17],"method":"keyword_and","location":"title","keywords":["Network Video Recorder Login"],"confidence":"高"},
    {"name":"群晖 NAS","cats":[23],"method":"keyword_and","location":"body","keywords":["Synology","webman/"],"confidence":"高"},
    {"name":"小米路由器","cats":[23],"method":"keyword_and","location":"body","keywords":["小米路由器","miwifi.com"],"confidence":"高"},

    # ===================== 云服务 / API =====================
    {"name":"Nacos","cats":[27],"method":"keyword_and","location":"body","keywords":["nacos","console-ui"],"confidence":"高"},
    {"name":"Sentinel","cats":[27],"method":"keyword_and","location":"body","keywords":["sentinel-dashboard"],"confidence":"高"},
    {"name":"Eureka","cats":[27],"method":"keyword_and","location":"body","keywords":["eureka","/eureka/"],"confidence":"高"},
    {"name":"Apollo","cats":[27],"method":"keyword_and","location":"body","keywords":["Apollo","apollo"],"confidence":"中"},
    {"name":"H2 Database Console","cats":[10],"method":"favicon","favicon_hash":-525659379,"confidence":"中"},
    {"name":"Kubernetes Dashboard","cats":[27],"method":"keyword_and","location":"body","keywords":["kubernetes-dashboard","k8s-dashboard"],"confidence":"高"},
    {"name":"MinIO","cats":[27],"method":"keyword_and","location":"body","keywords":["MinIO","minio"],"confidence":"高"},

    # ===================== 安全设备 =====================
    {"name":"安全狗 (SafeDog)","cats":[9],"method":"keyword_and","location":"body","keywords":["SafeDog","安全狗"],"confidence":"高"},
    {"name":"D盾","cats":[9],"method":"keyword_and","location":"body","keywords":["D.D.Waf","D盾"],"confidence":"高"},
    {"name":"长亭 SafeLine","cats":[9],"method":"keyword_and","location":"body","keywords":["SafeLine","chaitin"],"confidence":"高"},
    {"name":"360天擎","cats":[9],"method":"keyword_and","location":"body","keywords":["天擎","360EntInst"],"confidence":"高"},
    {"name":"网防G01","cats":[9],"method":"favicon","favicon_hash":-968234332,"confidence":"高"},
    {"name":"绿盟安全设备","cats":[9],"method":"keyword_and","location":"header","keywords":["NSFOCUS"],"confidence":"高"},

    # ===================== 教育/医疗/其他 =====================
    {"name":"正方教务系统","cats":[25],"method":"keyword_and","location":"body","keywords":["教务系统","正方软件"],"confidence":"中"},
    {"name":"强智教务系统","cats":[25],"method":"keyword_and","location":"body","keywords":["强智科技","教务"],"confidence":"中"},
    {"name":"宏景 eHR","cats":[24],"method":"keyword_and","location":"body","keywords":["人力资源信息管理系统","hrlogon"],"confidence":"高"},
    {"name":"MeterSphere","cats":[20],"method":"favicon","favicon_hash":1023469568,"confidence":"高"},
    {"name":"宝塔面板","cats":[7],"method":"keyword_and","location":"body","keywords":["bt.cn","面板"],"confidence":"高"},
    {"name":"DRUID 监控","cats":[12],"method":"keyword_and","location":"body","keywords":["Druid","druid monitor"],"confidence":"高"},
    {"name":"FastAdmin","cats":[1],"method":"keyword_and","location":"body","keywords":["FastAdmin","fastadmin"],"confidence":"中"},
    {"name":"若依 (RuoYi)","cats":[6],"method":"keyword_and","location":"body","keywords":["ruoyi","若依"],"confidence":"高"},
    {"name":"Spring Boot Actuator","cats":[6],"method":"keyword_and","location":"body","keywords":["Whitelabel Error Page"],"confidence":"高"},
    {"name":"GitLab","cats":[20],"method":"keyword_and","location":"body","keywords":["assets/gitlab_logo"],"confidence":"高"},
    {"name":"Gitblit","cats":[20],"method":"keyword_and","location":"body","keywords":["gitblit","gitblt-favicon.png"],"confidence":"高"},
    {"name":"Confluence","cats":[20],"method":"keyword_and","location":"body","keywords":["confluence","confluence-base"],"confidence":"高"},
    {"name":"Jira","cats":[20],"method":"keyword_and","location":"body","keywords":["jira","jira.webresources"],"confidence":"高"},
    {"name":"禅道 (Zentao)","cats":[4],"method":"keyword_and","location":"body","keywords":["zentao","zentaoPHP"],"confidence":"高"},
]

# Favicon hash 快速查找
HUB_FAVICON_MAP = {}
for fp in HUB_FINGERPRINTS:
    if fp.get("method") == "favicon" and isinstance(fp.get("favicon_hash"), int):
        HUB_FAVICON_MAP[fp["favicon_hash"]] = fp["name"]
