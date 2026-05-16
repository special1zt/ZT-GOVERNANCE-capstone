FROM splunk/universalforwarder:latest

USER root
COPY forwarder_app/local/inputs.conf /opt/splunkforwarder/etc/apps/search/local/inputs.conf
COPY forwarder_app/local/outputs.conf /opt/splunkforwarder/etc/system/local/outputs.conf
RUN chown -R splunk:splunk /opt/splunkforwarder/etc/apps/search/local /opt/splunkforwarder/etc/system/local
