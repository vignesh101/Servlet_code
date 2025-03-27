.and()
.headers()
.cacheControl()
.and()
.httpStrictTransportSecurity()
.and()
.frameOptions()
.deny()


response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        response.setHeader("Pragma", "no-cache");
        response.setDateHeader("Expires", 0);
