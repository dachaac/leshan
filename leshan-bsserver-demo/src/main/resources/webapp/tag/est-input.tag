<est-input>
    <!-- X.509 inputs -->
    <div class={ form-group:true, has-error: x509ServerCert.error }>
        <label for="x509ServerCert" class="col-sm-4 control-label">Server certificate</label>
        <div class="col-sm-8">
            <textarea class="form-control" style="resize:none" rows="3" id="x509ServerCert" ref="x509ServerCert" oninput={validate_x509ServerCert} onblur={validate_x509ServerCert} disabled={disable.servercertificate} placeholder={servercertificate}></textarea>
            <p class="text-right text-muted small" style="margin:0">Hexadecimal format</p>
            <p class="help-block" if={x509ServerCert.required}>The server certificate is required</p>
            <p class="help-block" if={x509ServerCert.nothexa}>Hexadecimal format is expected</p>
        </div>
    </div>

    <script>
        // Tag definition
        var tag = this;
        // Tag Params
        tag.onchange = opts.onchange;
        tag.disable = opts.disable || {};
        tag.servercertificate = opts.servercertificate || "";
        // Tag API
        tag.has_error = has_error;
        tag.get_value = get_value
        // Tag intenal state
        tag.x509ServerCert = {};
        tag.validate_x509ServerCert = validate_x509ServerCert;

        // Tag functions
        function validate_x509ServerCert(){
            var str = tag.refs.x509ServerCert.value || tag.servercertificate;
            tag.x509ServerCert.error = false;
            tag.x509ServerCert.required = false;
            tag.x509ServerCert.nothexa = false;
            if (!str || 0 === str.length){
                  tag.x509ServerCert.error = true;
                  tag.x509ServerCert.required = true;
              }else if (! /^[0-9a-fA-F]+$/i.test(str)){
                  tag.x509ServerCert.error = true;
                  tag.x509ServerCert.nothexa = true;
            }
            tag.onchange();
        }

        function has_error(){
            console.log()
            return (tag.servercertificate === "" && (typeof tag.x509ServerCert.error === "undefined" || tag.x509ServerCert.error));
        }

        function get_value(){
            return { servCert:tag.refs.x509ServerCert.value || tag.servercertificate };
        }
    </script>
</est-input>