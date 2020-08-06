## HTTP Request Firewall

Blocks common malicious HTTP traffic and reduces load on the application.

Inspired by the following:

  https://perishablepress.com/7g-firewall/ (check there for updated patterns and watch for the 8g and future updates)
  
  https://unforgettable.dk (get the 42.zip file from here)
  
  https://en.wikipedia.org/wiki/Rickrolling


## USAGE: 
To run just "new up" the class:

    new HttpRequestFirewall;
    // this will immediately run all inspections, without logging
  
Or to enable logging:

    $firewall = new HttpRequestFirewall(false);
    $firewall->logToFile();
    $firewall->inspect();
  
or optionally set a filename using:

    $firewall = new HttpRequestFirewall(false);
    $firewall->logToFile('path_to_logfile.log');   // note: `.log` suffix will be appended if not included
    $firewall->inspect();

If the `42.zip` file is not found in the same directory, then the visitor will be directed to the video.

NOTE: This handles HTTP request traffic only. It is irrelevant for command-line traffic, and should not be avoided for command line.
