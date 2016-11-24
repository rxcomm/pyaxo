def test_init_state(axolotl_a, axolotl_b, exchange):
    axolotl_a.initState(other_name=axolotl_b.name,
                        other_identityKey=axolotl_b.state['DHIs'],
                        other_handshakeKey=axolotl_b.handshakePKey,
                        other_ratchetKey=axolotl_b.state['DHRs'],
                        verify=False)

    axolotl_b.initState(other_name=axolotl_a.name,
                        other_identityKey=axolotl_a.state['DHIs'],
                        other_handshakeKey=axolotl_a.handshakePKey,
                        other_ratchetKey=axolotl_a.state['DHRs'],
                        verify=False)

    exchange(axolotl_a, axolotl_b)


def test_create_state(axolotl_a, axolotl_b, exchange):
    mkey = 'masterkey'

    axolotl_a.createState(other_name=axolotl_b.name,
                          mkey=mkey,
                          mode=True,
                          other_ratchetKey=axolotl_b.state['DHRs'])
    axolotl_b.createState(other_name=axolotl_a.name,
                          mkey=mkey,
                          mode=False)

    exchange(axolotl_a, axolotl_b)
