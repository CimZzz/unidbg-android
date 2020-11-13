package com.bytedance.frameworks.core.encrypt;

import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.debugger.DebuggerType;
import com.github.unidbg.debugger.ida.AndroidServer;
import com.github.unidbg.linux.android.AndroidARMEmulator;

public class TestEmu extends AndroidARMEmulator {

    public TestEmu(String processName) {
        super(processName, null);
    }

    @Override
    public Debugger attach(DebuggerType type) {
        return new AndroidServer(this, (byte)22);
    }
}
