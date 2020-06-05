# Sysax-MultiServer-6.90-Multiple-Vulnerabilities

<p>Multiple vulnerabilities were discovered in Sysax Multi Server 6.90.</p>
<p>*** Vendor was informed on May 19th, 2020 but I have not received any feedback ***</p>
<p><strong>1) Insecure Permissions and Information Disclosure via error handling</strong><br />::: CVE-2020-13227 :::</p>
<p>An attacker can determine the username (under which the web server is running) by triggering an invalid path permission error. This bypasses the fakepath protection mechanism.</p>
<p>PoC:</p>
<div><a href="http://192.168.88.131/scgi?sid=7d2ec36cd2f0a42929a5672c9cc5f0320a666155&amp;pid=transferpage2_name1_(folder" target="_blank" rel="noopener" data-saferedirecturl="https://www.google.com/url?q=http://192.168.88.131/scgi?sid%3D7d2ec36cd2f0a42929a5672c9cc5f0320a666155%26pid%3Dtransferpage2_name1_(folder&amp;source=gmail&amp;ust=1591449741235000&amp;usg=AOvVaw3-JyvWkyrWn2HgYasPEgsq">http://192.168.88.131/scgi?<wbr />sid=<wbr />7d2ec36cd2f0a42929a5672c9cc5f0<wbr />320a666155&amp;pid=transferpage2_<wbr />name1_(folder</a>&nbsp;where you don't have permissions).htm</div>
<div>E.g</div>
<div><a href="http://192.168.88.131/scgi?sid=7d2ec36cd2f0a42929a5672c9cc5f0320a666155&amp;pid=transferpage2_name1_johnfolder.htm" target="_blank" rel="noopener" data-saferedirecturl="https://www.google.com/url?q=http://192.168.88.131/scgi?sid%3D7d2ec36cd2f0a42929a5672c9cc5f0320a666155%26pid%3Dtransferpage2_name1_johnfolder.htm&amp;source=gmail&amp;ust=1591449741235000&amp;usg=AOvVaw2u3Mq42cAbcQFNTA8MUSfa">http://192.168.88.131/scgi?<wbr />sid=<wbr />7d2ec36cd2f0a42929a5672c9cc5f0<wbr />320a666155&amp;pid=transferpage2_<wbr />name1_johnfolder.htm</a>&nbsp;&nbsp;</div>
<p>PoC screen: https://pasteboard.co/J9eF12G.png</p>
<p><strong>2) Reflected Cross Site Scripting (XSS)</strong><br />::: CVE-2020-13228 :::</p>
<p>There is a reflected XSS via the /scgi sid parameter.</p>
<p>PoC Screen: https://pasteboard.co/J9eE2GQ.png</p>
<p><strong>3) Incorrect Access Control - Session Fixation</strong><br />::: CVE-2020-13229 :::</p>
<p>A session can be hijacked if one observes the sid value in any /scgi URI, because it is an authentication token.<br /> <br /> PoC:<br /> When the user is logged on, URI something like this is generated: http://192.168.88.131/scgi?sid=684216c78659562c92775c885e956585cdb180fd&amp;pid=mk_folder1_name1.htm<br /> Considering that "sid" parameter is the auth token of the user (passed in GET), simply replacing the complete URI in any session (changing the browser), you will have the access to that user without the necessity to perform login.</p>
