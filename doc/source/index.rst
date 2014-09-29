Python bindings to the Group Based Policy API
=============================================

In order to use the python group-based-policy- client directly, you must first obtain an auth token and identify which endpoint you wish to speak to. Once you have done so, you can use the API like so::

    >>> import logging
    >>> from gbpclient.gbp import client
    >>> logging.basicConfig(level=logging.DEBUG)
    >>> gbp = client.Client('2.0', endpoint_url=OS_URL, token=OS_TOKEN)
    >>> gbp.format = 'json'
    >>> ptg = {'name': 'my_ptg'}
    >>> gbp.create_policy_target_group({'policy_target_group':ptg})
    >>> policy_target_groups = gbp.list_policy_target_groups(name='my_ptg')
    >>> print policy_target_groups
    >>> ptg_id = policy_target_groups['policy_target_groups'][0]['id']
    >>> gbp.delete_policy_target_group(ptg_id)


Command-line Tool
=================
In order to use the CLI, you must provide your OpenStack username, password, tenant, and auth endpoint. Use the corresponding configuration options (``--os-username``, ``--os-password``, ``--os-tenant-name``, and ``--os-auth-url``) or set them in environment variables::

    export OS_USERNAME=user
    export OS_PASSWORD=pass
    export OS_TENANT_NAME=tenant
    export OS_AUTH_URL=http://auth.example.com:5000/v2.0

The command line tool will attempt to reauthenticate using your provided credentials for every request. You can override this behavior by manually supplying an auth token using ``--os-url`` and ``--os-auth-token``. You can alternatively set these environment variables::

    export OS_URL=http://neutron.example.org:9696/
    export OS_TOKEN=3bcc3d3a03f44e3d8377f9247b0ad155

If neutron server does not require authentication, besides these two arguments or environment variables (We can use any value as token.), we need manually supply ``--os-auth-strategy`` or set the environment variable::

    export OS_AUTH_STRATEGY=noauth

Once you've configured your authentication parameters, you can run ``gbp -h`` to see a complete listing of available commands.

Release Notes
=============

