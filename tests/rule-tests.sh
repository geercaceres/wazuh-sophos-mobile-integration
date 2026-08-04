#!/bin/bash
# Feed crafted records through wazuh-logtest and report which rule fires.
LT=/var/ossec/bin/wazuh-logtest
PASS=0; FAIL=0

run() {
  local label="$1" expect="$2" line="$3"
  local out rule lvl desc
  out=$(printf '%s\n' "$line" | $LT 2>&1)
  rule=$(echo "$out" | grep -oP "^\s+id: '\K[0-9]+" | tail -1)
  lvl=$(echo "$out" | grep -oP "level: '\K[0-9]+" | tail -1)
  desc=$(echo "$out" | grep -oP "description: '\K[^']+" | tail -1)
  if [ "$rule" = "$expect" ]; then
    PASS=$((PASS+1)); printf "  PASS  %-52s -> %s (lvl %s)\n" "$label" "$rule" "$lvl"
  else
    FAIL=$((FAIL+1)); printf "  FAIL  %-52s -> expected %s, got %s\n" "$label" "$expect" "${rule:-none}"
    echo "        desc: $desc"
  fi
}

ev() { # ev <severity> <name> <type>
  printf '{"integration":"sophos_mobile","sophos_record":"event","sophos":{"endpoint_type":"mobile","location":"pixel-7","severity":"%s","name":"%s","type":"%s","group":"MOBILES"}}' "$1" "$2" "$3"
}
vio() { # vio <platform> <violation json body>
  printf '{"integration":"sophos_mobile","sophos_record":"compliance_violation","sophos":{"deviceId":"d1","deviceName":"pixel-7","os":{"platform":"%s"},"violation":%s,"violationText":%s}}' "$1" "$2" "$(printf '%s' "$2" | /var/ossec/framework/python/bin/python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
}

echo "======== CATCH-ALL (nothing is ever dropped) ========"
run "unknown record type falls through to base rule" 100600 \
'{"integration":"sophos_mobile","sophos_record":"some_future_thing","sophos":{"foo":"bar"}}'
run "event with no matching child, low severity" 100601 \
"$(ev low 'Something totally new happened' 'Event::Endpoint::Mobile::Whatever')"

echo
echo "======== ANDROID: root / jailbreak ========"
run "root access event (by name)" 100648 "$(ev high 'Root access detected on device' 'Event::Endpoint::Mobile::NotCompliant')"
run "rooted wording" 100648 "$(ev medium 'Device is rooted' 'Event::Endpoint::Mobile::Whatever')"
run "iOS jailbroken wording" 100648 "$(ev high 'Device is jailbroken' 'Event::Endpoint::Mobile::NotCompliant')"
run "root violation payload" 100630 "$(vio android '{"rule":"Root access allowed","state":"violated"}')"
run "jailbreak violation payload" 100630 "$(vio ios '{"rule":"Allow jailbreak","state":"violated"}')"

echo
echo "======== ANDROID: malware / PUA (ordering vs severity fallback) ========"
run "Threat::Detected beats severity fallback" 100641 "$(ev high 'Malware detected: Android/Trojan' 'Event::Endpoint::Threat::Detected')"
run "PuaDetected type" 100643 "$(ev medium 'PUA found' 'Event::Endpoint::Threat::PuaDetected')"
run "malware by name only" 100642 "$(ev high 'Malware apps allowed rule violated' 'Event::Endpoint::Mobile::Foo')"
run "suspicious app by name" 100649 "$(ev medium 'Suspicious app installed' 'Event::Endpoint::Mobile::Foo')"
run "malware violation payload" 100631 "$(vio android '{"rule":"Malware apps allowed","app":"com.evil.bank"}')"
run "suspicious violation payload" 100632 "$(vio android '{"rule":"Suspicious apps allowed"}')"
run "PUA violation payload" 100632 "$(vio android '{"rule":"PUAs allowed"}')"

echo
echo "======== ANDROID: ADB, encryption, apps, screenlock ========"
run "ADB event" 100636 "$(ev medium 'Android Debug Bridge (ADB) allowed violated' 'Event::Endpoint::Mobile::Foo')"
run "ADB violation payload" 100633 "$(vio android '{"rule":"Android Debug Bridge (ADB) allowed"}')"
run "encryption event" 100637 "$(ev medium 'Encryption required rule violated' 'Event::Endpoint::Mobile::Foo')"
run "encryption violation payload" 100634 "$(vio android '{"rule":"Encryption required"}')"
run "mandatory apps event" 100638 "$(ev medium 'Mandatory apps missing' 'Event::Endpoint::Mobile::Foo')"
run "forbidden app violation payload" 100635 "$(vio android '{"rule":"Installed apps","app":"com.tiktok"}')"
run "screen lock event" 100639 "$(ev low 'Screen lock required violated' 'Event::Endpoint::Mobile::Foo')"
run "OS version violation payload" 100640 "$(vio android '{"rule":"Minimum OS version","required":"13"}')"
run "MTD scan interval violation" 100640 "$(vio android '{"rule":"Maximum interval between Intercept X for Mobile scans"}')"

echo
echo "======== app inventory records ========"
run "installed_app" 100626 \
'{"integration":"sophos_mobile","sophos_record":"installed_app","sophos":{"deviceId":"d1","deviceName":"pixel-7","os":{"platform":"android"},"appIdentifier":"com.whatsapp","appName":"WhatsApp","app":{"identifier":"com.whatsapp","name":"WhatsApp"}}}'
run "app_removed" 100627 \
'{"integration":"sophos_mobile","sophos_record":"app_removed","sophos":{"deviceId":"d1","deviceName":"pixel-7","os":{"platform":"android"},"appIdentifier":"com.whatsapp"}}'
run "forbidden_app" 100628 \
'{"integration":"sophos_mobile","sophos_record":"forbidden_app","sophos":{"deviceId":"d1","deviceName":"pixel-7","os":{"platform":"android"},"appIdentifier":"com.zhiliaoapp.musically","appName":"TikTok","matchedPattern":"(?i)tiktok","app":{"identifier":"com.zhiliaoapp.musically","name":"TikTok"}}}'

echo
echo "======== alerts ========"
run "alert mentioning malware" 100619 \
'{"integration":"sophos_mobile","sophos_record":"alert","sophos":{"severity":"medium","description":"Malicious app detected on pixel-7","type":"Event::Endpoint::Threat::Detected"}}'
run "alert high severity generic" 100618 \
'{"integration":"sophos_mobile","sophos_record":"alert","sophos":{"severity":"high","description":"Something bad","type":"Event::Endpoint::Foo"}}'
run "alert low severity generic" 100617 \
'{"integration":"sophos_mobile","sophos_record":"alert","sophos":{"severity":"low","description":"FYI","type":"Event::Endpoint::Foo"}}'

echo
echo "======== REGRESSION: previously verified behaviour ========"
DEV='"id":"00000000-0000-0000-0000-000000000000","name":"test-device-01","os":{"platform":"windows","name":"Windows 10.0.26200.8973"},"managementType":"fullMdm"'
run "real device payload (compliant/managed/green)" 100620 \
"{\"integration\":\"sophos_mobile\",\"sophos_record\":\"device_status\",\"sophos\":{$DEV,\"compliance\":{\"compliant\":true},\"managedState\":\"managed\",\"healthState\":{\"state\":\"green\"}}}"
run "device NON-COMPLIANT (compliant=false)" 100621 \
"{\"integration\":\"sophos_mobile\",\"sophos_record\":\"device_status\",\"sophos\":{$DEV,\"compliance\":{\"compliant\":false},\"managedState\":\"managed\",\"healthState\":{\"state\":\"green\"}}}"
run "device unmanaged (negate)" 100622 \
"{\"integration\":\"sophos_mobile\",\"sophos_record\":\"device_status\",\"sophos\":{$DEV,\"compliance\":{\"compliant\":true},\"managedState\":\"pendingRemoval\",\"healthState\":{\"state\":\"green\"}}}"
run "device health red" 100623 \
"{\"integration\":\"sophos_mobile\",\"sophos_record\":\"device_status\",\"sophos\":{$DEV,\"compliance\":{\"compliant\":true},\"managedState\":\"managed\",\"healthState\":{\"state\":\"red\"}}}"
run "real event: NowCompliant" 100610 "$(ev low 'The mobile device is now compliant' 'Event::Endpoint::Mobile::NowCompliant')"
run "real event: Enrolled" 100613 "$(ev low 'New mobile device enrolled' 'Event::Endpoint::Mobile::Enrolled')"
run "real event: Added" 100613 "$(ev low 'New mobile device added' 'Event::Endpoint::Mobile::Added')"
run "real event: Action::Succeeded -> base" 100601 "$(ev low 'Enrollment succeeded' 'Event::Endpoint::Mobile::Action::Succeeded')"
run "generic NonCompliant type" 100611 "$(ev medium 'Device is not in line with policy' 'Event::Endpoint::NonCompliant')"
run "Action::Failed" 100615 "$(ev low 'Lock device failed' 'Event::Endpoint::Mobile::Action::Failed')"
run "device removed" 100614 "$(ev low 'Mobile device deleted' 'Event::Endpoint::Mobile::Removed')"
run "management suspended" 100646 "$(ev medium 'Protection suspended' 'Event::Endpoint::Management::Suspended')"
run "out of date" 100647 "$(ev low 'Device out of date' 'Event::Endpoint::OutOfDate')"
run "medium severity fallback" 100602 "$(ev medium 'Unclassified thing' 'Event::Endpoint::Mobile::Zzz')"
run "high severity fallback" 100603 "$(ev high 'Unclassified bad thing' 'Event::Endpoint::Mobile::Zzz')"

echo
echo "================ $PASS passed, $FAIL failed ================"
