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
    gbp endpointgroup-delete ptg_name
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
gbp endpointgroup-create $FORMAT $NOAUTH $ptg || die "fail to create ptg $ptg"
temp=`gbp endpointgroup-list $FORMAT -- --name $ptg --fields id | wc -l`
echo $temp
if [ $temp -ne 5 ]; then
   die "PTGs with name $ptg is not unique or found"
fi
ptg_id=`gbp gbp-list -- --name $ptg --fields id | tail -n 2 | head -n 1 |  cut -d' ' -f 2`
echo "ID of PTG with name $ptg is $ptg_id"

gbp endpointgroup-show $FORMAT $ptg ||  die "fail to show PTG $ptg"
gbp endpointgroup-show $FORMAT $ptg_id ||  die "fail to show PTG $ptg_id"

gbp endpointgroup-update $FORMAT $ptg --description "desc" ||  die "fail to update PTG $ptg"
gbp endpointgroup-update $FORMAT $ptg_id --description "new" ||  die "fail to update PTG $ptg_id"

gbp endpointgroup-list $FORMAT -c id -- --id fakeid  || die "fail to list PTGs with column selection on empty list"

cleanup
echo "Success! :)"

