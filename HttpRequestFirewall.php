<?php
/** 
 * Request Firewall
 * Blocks common malicious traffic and reduces load on the application
 * 
 * Inspired by the following:
 * https://perishablepress.com/7g-firewall/ (check this site for updated patterns and watch for the 8g and future updates)
 * https://unforgettable.dk (get the 42.zip file from here)
 * https://en.wikipedia.org/wiki/Rickrolling
 *
 *
 * USAGE: 
 * To run just "new up" the class:
 *   new HttpRequestFirewall;
 *   
 * Or to enable logging:
 *   $firewall = new HttpRequestFirewall(false);
 *   $firewall->logToFile();
 *   $firewall->inspect();
 *   
 *  or optionally set a filename using:
 *   $firewall = new HttpRequestFirewall(false);
 *   $firewall->logToFile('path_to_logfile.log');   // note: ".log" will be appended if not included
 *   $firewall->inspect();
 *
 *  If the 42.zip file is not found, then the user will be directed to the video.
  */

class HttpRequestFirewall
{
    protected $payload_gzip_file = '42.zip';
    protected $rickroll_url = 'https://www.youtube.com/watch?v=dQw4w9WgXcQ';

    // set this to true to record what caused all requests to be blocked
    protected $logging_enabled = false;

    protected $logfile = 'blocked_requests.log';


    public function __construct($run_immediately = true)
    {
        if ($run_immediately) {
            $this->inspect();
        }
    }

    public function logToFile($path)
    {
        $status = false;
        if (empty($path)) {
            $path = $this->logfile;
        }
        if (substr($path, -4) !== '.log') {
            $path .= '.log';
        }
        if (file_exists($path)) {
            $status = true;
        } else {
            $status = file_put_contents($path, 'Logfile initialized', FILE_APPEND);
        }
        if ($status !== false) {
            $this->logging_enabled = true;
            $this->logfile = $path;
        }

        return $this->logging_enabled ? $this->logfile : false;
    }

    public function inspect()
    {
        $this->doUserAgent();
        $this->doQueryString();
        $this->doRequestUri();
        $this->doRemoteHost();
        $this->doHttpReferrer();
        $this->doRequestMethod();
    }

    protected function doUserAgent()
    {
        $bad_useragents_patterns = [];
        $bad_useragents_patterns[] = '([a-z0-9]{2000,})';
        $bad_useragents_patterns[] = '(&lt;|%0a|%0d|%27|%3c|%3e|%00|0x00)';
        $bad_useragents_patterns[] = '((c99|php|web)shell|remoteview|site((.){0,2})copier)';
        $bad_useragents_patterns[] = '(base64_decode|bin/bash|disconnect|eval|lwp-download|unserialize|\\\x22)';
        $bad_useragents_patterns[] = '(360Spider|acapbot|acoonbot|ahrefs|alexibot|asterias|attackbot|backdorbot|becomebot|binlar|blackwidow|blekkobot|blexbot|blowfish|bullseye|bunnys|butterfly|careerbot|casper|checkpriv|cheesebot|cherrypick|chinaclaw|choppy|clshttp|cmsworld|copernic|copyrightcheck|cosmos|crescent|cy_cho|datacha|demon|diavol|discobot|dittospyder|dotbot|dotnetdotcom|dumbot|emailcollector|emailsiphon|emailwolf|exabot|extract|eyenetie|feedfinder|flaming|flashget|flicky|foobot|g00g1e|getright|gigabot|go-ahead-got|gozilla|grabnet|grafula|harvest|heritrix|httrack|icarus6j|jetbot|jetcar|jikespider|kmccrew|leechftp|libweb|linkextractor|linkscan|linkwalker|loader|miner|majestic|mechanize|mj12bot|morfeus|moveoverbot|netmechanic|netspider|nicerspro|nikto|ninja|nutch|octopus|pagegrabber|planetwork|postrank|proximic|purebot|pycurl|python|queryn|queryseeker|radian6|radiation|realdownload|rogerbot|scooter|seekerspider|semalt|seznambot|siclab|sindice|sistrix|sitebot|siteexplorer|sitesnagger|skygrid|smartdownload|snoopy|sosospider|spankbot|spbot|sqlmap|stackrambler|stripper|sucker|surftbot|sux0r|suzukacz|suzuran|takeout|teleport|telesoft|true_robots|turingos|turnit|vampire|vikspider|voideye|webleacher|webreaper|webstripper|webvac|webviewer|webwhacker|winhttp|wwwoffle|woxbot|xaldon|xxxyy|yamanalab|yioopbot|youda|zeus|zmeu|zune|zyborg)';

        foreach ($bad_useragents_patterns as $pattern) {
            if (preg_match('~'.preg_quote($pattern, '~').'~', $src = filter_input(INPUT_SERVER, $type = 'HTTP_USER_AGENT'))) {
                if ($this->logging_enabled) $this->logReasonForBlocking($type, $pattern, $src);
                $this->exitWithPayload();
            }
        }
    }

    protected function doQueryString()
    {
        $bad_querystring_patterns = [];
        $bad_querystring_patterns[] = '([a-z0-9]{2000,})';
        $bad_querystring_patterns[] = '(/|%2f)(:|%3a)(/|%2f)';
        $bad_querystring_patterns[] = '(/|%2f)(\*|%2a)(\*|%2a)(/|%2f)';
        $bad_querystring_patterns[] = '(~|`|<|>|\^|\|\\|0x00|%00|%0d%0a)';
        $bad_querystring_patterns[] = '(cmd|command)(=|%3d)(chdir|mkdir)(.*)(x20)';
        $bad_querystring_patterns[] = '(fck|ckfinder|fullclick|ckfinder|fckeditor)';
        $bad_querystring_patterns[] = '(/|%2f)((wp-)?config)((\.|%2e)inc)?((\.|%2e)php)';
        $bad_querystring_patterns[] = '(thumbs?(_editor|open)?|tim(thumbs?)?)((\.|%2e)php)';
        $bad_querystring_patterns[] = '(absolute_|base|root_)(dir|path)(=|%3d)(ftp|https?)';
        $bad_querystring_patterns[] = '(localhost|loopback|127(\.|%2e)0(\.|%2e)0(\.|%2e)1)';
        $bad_querystring_patterns[] = '(\.|20)(get|the)(_|%5f)(permalink|posts_page_url)(\(|%28)';
        $bad_querystring_patterns[] = '(s)?(ftp|http|inurl|php)(s)?(:(/|%2f|%u2215)(/|%2f|%u2215))';
        $bad_querystring_patterns[] = '(globals|mosconfig([a-z_]{1,22})|request)(=|\[|%[a-z0-9]{0,2})';
        $bad_querystring_patterns[] = '((boot|win)((\.|%2e)ini)|etc(/|%2f)passwd|self(/|%2f)environ)';
        $bad_querystring_patterns[] = '(((/|%2f){3,3})|((\.|%2e){3,3})|((\.|%2e){2,2})(/|%2f|%u2215))';
        $bad_querystring_patterns[] = '(benchmark|char|exec|fopen|function|html)(.*)(\(|%28)(.*)(\)|%29)';
        $bad_querystring_patterns[] = '(php)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})';
        $bad_querystring_patterns[] = '(e|%65|%45)(v|%76|%56)(a|%61|%31)(l|%6c|%4c)(.*)(\(|%28)(.*)(\)|%29)';
        $bad_querystring_patterns[] = '(/|%2f)(=|%3d|$&|_mm|cgi(\.|-)|inurl(:|%3a)(/|%2f)|(mod|path)(=|%3d)(\.|%2e))';
        $bad_querystring_patterns[] = '(<|%3c)(.*)(e|%65|%45)(m|%6d|%4d)(b|%62|%42)(e|%65|%45)(d|%64|%44)(.*)(>|%3e)';
        $bad_querystring_patterns[] = '(<|%3c)(.*)(i|%69|%49)(f|%66|%46)(r|%72|%52)(a|%61|%41)(m|%6d|%4d)(e|%65|%45)(.*)(>|%3e)';
        $bad_querystring_patterns[] = '(<|%3c)(.*)(o|%4f|%6f)(b|%62|%42)(j|%4a|%6a)(e|%65|%45)(c|%63|%43)(t|%74|%54)(.*)(>|%3e)';
        $bad_querystring_patterns[] = '(<|%3c)(.*)(s|%73|%53)(c|%63|%43)(r|%72|%52)(i|%69|%49)(p|%70|%50)(t|%74|%54)(.*)(>|%3e)';
        $bad_querystring_patterns[] = '(\+|%2b|%20)(d|%64|%44)(e|%65|%45)(l|%6c|%4c)(e|%65|%45)(t|%74|%54)(e|%65|%45)(\+|%2b|%20)';
        $bad_querystring_patterns[] = '(\+|%2b|%20)(i|%69|%49)(n|%6e|%4e)(s|%73|%53)(e|%65|%45)(r|%72|%52)(t|%74|%54)(\+|%2b|%20)';
        $bad_querystring_patterns[] = '(\+|%2b|%20)(s|%73|%53)(e|%65|%45)(l|%6c|%4c)(e|%65|%45)(c|%63|%43)(t|%74|%54)(\+|%2b|%20)';
        $bad_querystring_patterns[] = '(\+|%2b|%20)(u|%75|%55)(p|%70|%50)(d|%64|%44)(a|%61|%41)(t|%74|%54)(e|%65|%45)(\+|%2b|%20)';
        $bad_querystring_patterns[] = '(\\x00|(\"|%22|\'|%27)?0(\"|%22|\'|%27)?(=|%3d)(\"|%22|\'|%27)?0|cast(\(|%28)0x|or%201(=|%3d)1)';
        $bad_querystring_patterns[] = '(g|%67|%47)(l|%6c|%4c)(o|%6f|%4f)(b|%62|%42)(a|%61|%41)(l|%6c|%4c)(s|%73|%53)(=|[|%[0-9A-Z]{0,2})';
        $bad_querystring_patterns[] = '(_|%5f)(r|%72|%52)(e|%65|%45)(q|%71|%51)(u|%75|%55)(e|%65|%45)(s|%73|%53)(t|%74|%54)(=|[|%[0-9A-Z]{0,2})';
        $bad_querystring_patterns[] = '(j|%6a|%4a)(a|%61|%41)(v|%76|%56)(a|%61|%31)(s|%73|%53)(c|%63|%43)(r|%72|%52)(i|%69|%49)(p|%70|%50)(t|%74|%54)(:|%3a)(.*)(;|%3b|\)|%29)';
        $bad_querystring_patterns[] = '(b|%62|%42)(a|%61|%41)(s|%73|%53)(e|%65|%45)(6|%36)(4|%34)(_|%5f)(e|%65|%45|d|%64|%44)(e|%65|%45|n|%6e|%4e)(c|%63|%43)(o|%6f|%4f)(d|%64|%44)(e|%65|%45)(.*)(\()(.*)(\))';
        $bad_querystring_patterns[] = '(allow_url_(fopen|include)|auto_prepend_file|blexbot|browsersploit|(c99|php)shell|curltest|disable_functions?|document_root|elastix|encodeuricom|exec|exploit|fclose|fgets|fputs|fsbuff|fsockopen|gethostbyname|grablogin|hmei7|input_file|load_file|null|open_basedir|outfile|passthru|popen|proc_open|quickbrute|remoteview|root_path|safe_mode|shell_exec|site((.){0,2})copier|sux0r|trojan|wget|xertive)';
        $bad_querystring_patterns[] = '(;|<|>|\'|\"|\)|%0a|%0d|%22|%27|%3c|%3e|%00)(.*)(/\*|alter|base64|benchmark|cast|char|concat|convert|create|encode|declare|delete|drop|md5|order|request|script|select|set|union)';
        $bad_querystring_patterns[] = '((\+|%2b)(concat|delete|get|select|union)(\+|%2b))';
        $bad_querystring_patterns[] = '(union)(.*)(select)(.*)(\(|%28)';
        $bad_querystring_patterns[] = '(concat)(.*)(\(|%28)';

        foreach ($bad_useragents_patterns as $pattern) {
            if (preg_match('~'.preg_quote($pattern, '~').'~', $src = filter_input(INPUT_SERVER, $type = 'QUERY_STRING'))) {
                if ($this->logging_enabled) $this->logReasonForBlocking($type, $pattern, $src);
                $this->exitWithPayload();
            }
        }
    }

    protected function doRequestUri()
    {
        $bad_uri_patterns = [];
        $bad_uri_patterns[] = '([a-z0-9]{2000,})';
        $bad_uri_patterns[] = '(=?\\(\'|%27)/?)(\.)';
        $bad_uri_patterns[] = '(/)(\*|\"|\'|\.|,|&|&amp;?)/?$';
        $bad_uri_patterns[] = '(\.)(php)(\()?([0-9]+)(\))?(/)?$';
        $bad_uri_patterns[] = '(/)(vbulletin|boards|vbforum)(/)?';
        $bad_uri_patterns[] = '(\^|~|`|<|>|,|%|\\|\{|\}|\[|\]|\|)';
        $bad_uri_patterns[] = '(\.(s?ftp-?)config|(s?ftp-?)config\.)';
        $bad_uri_patterns[] = '(\{0\}|\"?0\"?=\"?0|\(/\(|\.\.\.|\+\+\+|\\\")';
        $bad_uri_patterns[] = '(thumbs?(_editor|open)?|tim(thumbs?)?)(\.php)';
        $bad_uri_patterns[] = '(/)(fck|ckfinder|fullclick|ckfinder|fckeditor)';
        $bad_uri_patterns[] = '(\.|20)(get|the)(_)(permalink|posts_page_url)(\()';
        $bad_uri_patterns[] = '(///|\?\?|/&&|/\*(.*)\*/|/:/|\\\\|0x00|%00|%0d%0a)';
        $bad_uri_patterns[] = '(/%7e)(root|ftp|bin|nobody|named|guest|logs|sshd)(/)';
        $bad_uri_patterns[] = '(/)(etc|var)(/)(hidden|secret|shadow|ninja|passwd|tmp)(/)?$';
        $bad_uri_patterns[] = '(s)?(ftp|http|inurl|php)(s)?(:(/|%2f|%u2215)(/|%2f|%u2215))';
        $bad_uri_patterns[] = '(/)(=|\$&?|&?(pws|rk)=0|_mm|_vti_|cgi(\.|-)?|(=|/|;|,)nt\.)';
        $bad_uri_patterns[] = '(\.)(conf(ig)?|ds_store|htaccess|htpasswd|init?|mysql-select-db)(/)?$';
        $bad_uri_patterns[] = '(/)(bin)(/)(cc|chmod|chsh|cpp|echo|id|kill|mail|nasm|perl|ping|ps|python|tclsh)(/)?$';
        $bad_uri_patterns[] = '(/)(::[0-9999]|%3a%3a[0-9999]|127\.0\.0\.1|localhost|loopback|makefile|pingserver|wwwroot)(/)?';
        $bad_uri_patterns[] = '(\(null\)|\{\$itemURL\}|cAsT\(0x|echo(.*)kae|etc/passwd|eval\(|self/environ|\+union\+all\+select)';
        $bad_uri_patterns[] = '(/)(awstats|(c99|php|web)shell|document_root|error_log|listinfo|muieblack|remoteview|site((.){0,2})copier|sqlpatch|sux0r)';
        $bad_uri_patterns[] = '(/)((php|web)?shell|conf(ig)?|crossdomain|fileditor|locus7|nstview|php(get|remoteview|writer)|r57|remview|sshphp|storm7|webadmin)(.*)(\.|\()';
        $bad_uri_patterns[] = '(/)(author-panel|bitrix|class|database|(db|mysql)-?admin|filemanager|htdocs|httpdocs|https?|mailman|mailto|msoffice|mysql|_?php-?my-?admin(.*)|sql|system|tmp|undefined|usage|var|vhosts|webmaster|www)(/)';
        $bad_uri_patterns[] = '(base64_(en|de)code|benchmark|child_terminate|e?chr|eval|exec|function|fwrite|(f|p)open|html|leak|passthru|p?fsockopen|phpinfo|posix_(kill|mkfifo|setpgid|setsid|setuid)|proc_(close|get_status|nice|open|terminate)|(shell_)?exec|system)(.*)(\()(.*)(\))';
        $bad_uri_patterns[] = '(\.)(7z|ab4|afm|aspx?|bash|ba?k?|bz2|cfg|cfml?|cgi|conf(ig)?|ctl|dat|db|dll|eml|et2|exe|fec|fla|hg|inc|ini|inv|jsp|log|lqd|mbf|mdb|mmw|mny|old|one|out|passwd|pdb|pl|psd|pst|ptdb|pwd|py|qbb|qdf|rar|rdf|sdb|sql|sh|soa|swf|swl|swp|stx|tar|tax|tgz|tls|tmd|wow|zlib)$';
        $bad_uri_patterns[] = '(/)(^$|00.temp00|0day|3xp|70bex?|admin_events|bkht|(php|web)?shell|configbak|curltest|db|dompdf|filenetworks|hmei7|index\.php/index\.php/index|jahat|kcrew|keywordspy|mobiquo|mysql|nessus|php-?info|racrew|sql|ucp|webconfig|(wp-)?conf(ig)?(uration)?|xertive)(\.php)';

        $bad_uri_patterns[] = '(\.)(env|git)';
        $bad_uri_patterns[] = '(/)package-lock\.json';
        $bad_uri_patterns[] = '(/)(composer|yarn)\.lock';
        $bad_uri_patterns[] = '(/)(wp-admin|wp-login)';
        $bad_uri_patterns[] = '(/)xmlrpc\.php';


        foreach ($bad_referrer_patterns as $pattern) {
            if (preg_match('~'.preg_quote($pattern, '~').'~', $src = filter_input(INPUT_SERVER, $type = 'REQUEST_URI'))) {
                if ($this->logging_enabled) $this->logReasonForBlocking($type, $pattern, $src);
                $this->exitWithPayload();
            }
        }
    }

    protected function doRemoteHost()
    {
        $bad_host_pattern = '(163data|amazonaws|colocrossing|crimea|g00g1e|justhost|kanagawa|loopia|masterhost|onlinehome|poneytel|sprintdatacenter|reverse.softlayer|safenet|ttnet|woodpecker|wowrack)';

        if (preg_match('~'.preg_quote($bad_host_pattern, '~').'~', $src = filter_input(INPUT_SERVER, $type = 'REMOTE_HOST'))) {
            if ($this->logging_enabled) $this->logReasonForBlocking($type, $bad_host_pattern, $src);
            $this->exitWithPayload();
        }
    }

    protected function doHttpReferrer()
    {
        $bad_referrer_patterns = [];
        $bad_referrer_patterns[] = '/(semalt.com|todaperfeita)/';
        $bad_referrer_patterns[] = '/(ambien|blue\spill|cialis|cocaine|ejaculat|erectile|erections|hoodia|huronriveracres|impotence|levitra|libido|lipitor|phentermin|pro[sz]ac|sandyauer|tramadol|troyhamby|ultram|unicauca|valium|viagra|vicodin|xanax|ypxaieo)/';

        foreach ($bad_referrer_patterns as $pattern) {
            if (preg_match('~'.preg_quote($pattern, '~').'~', $src = filter_input(INPUT_SERVER, $type = 'HTTP_REFERER'))) {
                if ($this->logging_enabled) $this->logReasonForBlocking($type, $pattern, $src);
                $this->exitWithPayload();
            }
        }
    }

    protected function doRequestMethod()
    {
        $bad_requestmethod_pattern = '/^(connect|debug|delete|move|put|trace|track)/';

        if (preg_match($bad_requestmethod_pattern, $src = filter_input(INPUT_SERVER, $type = 'REQUEST_METHOD'))) {
            if ($this->logging_enabled) $this->logReasonForBlocking($type, $bad_requestmethod_pattern, $src);
            $this->exitWithPayload();
        }
    }

    function exitWithPayload() 
    {
        $this->sendGzipPayload();
        // if that didn't work then we just rickroll the visitor instead
        $this->sendRickrollPayload();
    }

    function sendGzipPayload()
    {
        if (file_exists($this->payload_gzip_file)) {
            http_response_code(404);
            header("Cache-Control: no-cache, must-revalidate"); // HTTP/1.1
            header("Expires: Sat, 26 Jul 1997 05:00:00 GMT"); // Date in the past
            header("Content-Encoding: gzip");
            header("Content-Length: " . filesize($this->payload_gzip_file));
            //Turn off output buffering
            if (ob_get_level()) ob_end_clean();
            //send the gzipped file to the client
            readfile($this->payload_gzip_file);
            exit;
        }       
    }

    function sendRickrollPayload()
    {
        http_response_code(404);
        header('Location: ' . $this->rickroll_url);
        exit;
    }

    protected function logReasonForBlocking($type, $pattern, $source)
    {
        file_put_contents($this->logfile, $type . ': ' . $pattern . ' in ' . $source, FILE_APPEND);
    }
}
