#!/bin/bash
set -x
function die() {
    local exitcode=$?
    set +o xtrace
    echo $@
    cleanup
    exit $exitcode
}

ptg_name=myptg1
## TODO Sumit: Test for other resources as well after renaming
function cleanup() {
    echo Removing test ptg...
    gbp policy-target-group-delete ptg_name
}

noauth_tenant_id=me
if [ "$1" == "noauth" ]; then
    NOAUTH="--tenant_id $noauth_tenant_id"
else
    NOAUTH=
fi

echo "NOTE: User should be admin in order to perform all operations."
sleep 3

FORMAT=" --request-format xml"

# test the CRUD of network
ptg=$ptg_name
gbp policy-target-group-create $FORMAT $NOAUTH $ptg || die "fail to create ptg $ptg"
temp=`gbp policy-target-group-list $FORMAT -- --name $ptg --fields id | wc -l`
echo $temp
if [ $temp -ne 5 ]; then
   die "PTGs with name $ptg is not unique or found"
fi
ptg_id=`gbp gbp-list -- --name $ptg --fields id | tail -n 2 | head -n 1 |  cut -d' ' -f 2`
echo "ID of PTG with name $ptg is $ptg_id"

gbp policy-target-group-show $FORMAT $ptg ||  die "fail to show PTG $ptg"
gbp policy-target-group-show $FORMAT $ptg_id ||  die "fail to show PTG $ptg_id"

gbp policy-target-group-update $FORMAT $ptg --description "desc" ||  die "fail to update PTG $ptg"
gbp policy-target-group-update $FORMAT $ptg_id --description "new" ||  die "fail to update PTG $ptg_id"

gbp policy-target-group-list $FORMAT -c id -- --id fakeid  || die "fail to list PTGs with column selection on empty list"

cleanup
echo "Success! :)"
