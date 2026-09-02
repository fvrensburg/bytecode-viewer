/***************************************************************************
 * Bytecode Viewer (BCV) - Java & Android Reverse Engineering Suite        *
 * Copyright (C) 2014 Konloch - Konloch.com / BytecodeViewer.com           *
 *                                                                         *
 * This program is free software: you can redistribute it and/or modify    *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation, either version 3 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 ***************************************************************************/

package the.bytecode.club.bytecodeviewer;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.*;
import the.bytecode.club.bytecodeviewer.util.ClassFileUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies that ASM can correctly read Java 25 class files (major version 69)
 * and that the expected constant pool entries are present.
 */
class BytecodeReaderTest
{
    /**
     * A simple fixture with predictable constant pool entries used as the class under test.
     * Compiled with Java 25 (major version 69).
     */
    static class Fixture
    {
        static final String GREETING = "Hello, Java 25!";
        private int value;

        Fixture(int value)
        {
            this.value = value;
        }

        String greet()
        {
            return GREETING;
        }
    }

    @Test
    void readClassFile() throws IOException
    {
        byte[] bytes = ClassFileUtils.getClassFileBytes(Fixture.class);

        // ── Class-file header ───────────────────────────────────────────────────
        // Magic: 0xCAFEBABE (bytes 0-3)
        assertEquals(0xCA, bytes[0] & 0xFF, "Magic byte 0 must be 0xCA");
        assertEquals(0xFE, bytes[1] & 0xFF, "Magic byte 1 must be 0xFE");
        assertEquals(0xBA, bytes[2] & 0xFF, "Magic byte 2 must be 0xBA");
        assertEquals(0xBE, bytes[3] & 0xFF, "Magic byte 3 must be 0xBE");

        // Minor version (bytes 4-5), major version (bytes 6-7)
        int minorVersion = ((bytes[4] & 0xFF) << 8) | (bytes[5] & 0xFF);
        int majorVersion = ((bytes[6] & 0xFF) << 8) | (bytes[7] & 0xFF);

        // Java 25 class files must have major version 69 (0x0045)
        assertEquals(69, majorVersion,
            "Expected Java 25 class file major version 69, got " + majorVersion);
        assertEquals(0, minorVersion,
            "Non-preview Java 25 class files must have minor version 0, got " + minorVersion);

        // ── ASM parse ───────────────────────────────────────────────────────────
        // ASM 9.9.1 ships with Opcodes.V25 = 69; verify the version constant aligns
        assertEquals(Opcodes.V25, majorVersion,
            "ASM Opcodes.V25 constant must match the Java 25 major version");

        ClassReader cr = new ClassReader(bytes);

        List<String> classRefs   = new ArrayList<>();
        List<String> fieldNames  = new ArrayList<>();
        List<String> methodNames = new ArrayList<>();
        List<Object> ldcValues   = new ArrayList<>();

        cr.accept(new ClassVisitor(Opcodes.ASM9)
        {
            @Override
            public void visit(int version, int access, String name,
                              String signature, String superName, String[] interfaces)
            {
                // CONSTANT_Class entries for 'this' class and its superclass
                classRefs.add(name);
                if (superName != null)
                    classRefs.add(superName);
            }

            @Override
            public FieldVisitor visitField(int access, String name, String descriptor,
                                           String signature, Object value)
            {
                // CONSTANT_Utf8 entries for field names; static finals carry ConstantValue
                fieldNames.add(name);
                if (value != null)
                    ldcValues.add(value);  // ConstantValue attribute (e.g. GREETING)
                return super.visitField(access, name, descriptor, signature, value);
            }

            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions)
            {
                // CONSTANT_Utf8 entries for method names
                methodNames.add(name);
                return new MethodVisitor(Opcodes.ASM9)
                {
                    @Override
                    public void visitLdcInsn(Object value)
                    {
                        // CONSTANT_String / CONSTANT_Integer / CONSTANT_Float etc.
                        ldcValues.add(value);
                    }
                };
            }
        }, 0);

        // ── Constant pool assertions (Java 25 output) ───────────────────────────
        // CONSTANT_Class: this class and its superclass
        String expectedInternalName =
            "the/bytecode/club/bytecodeviewer/BytecodeReaderTest$Fixture";
        assertTrue(classRefs.contains(expectedInternalName),
            "Constant pool must contain CONSTANT_Class for Fixture: " + classRefs);
        assertTrue(classRefs.contains("java/lang/Object"),
            "Constant pool must contain CONSTANT_Class for java/lang/Object: " + classRefs);

        // CONSTANT_Utf8 / ConstantValue: field names
        assertTrue(fieldNames.contains("GREETING"),
            "Constant pool must contain Utf8 'GREETING': " + fieldNames);
        assertTrue(fieldNames.contains("value"),
            "Constant pool must contain Utf8 'value': " + fieldNames);

        // CONSTANT_String (static-final initialiser captured as ConstantValue attribute)
        assertTrue(ldcValues.contains("Hello, Java 25!"),
            "Constant pool must contain CONSTANT_String 'Hello, Java 25!': " + ldcValues);

        // CONSTANT_Utf8 for method names
        assertTrue(methodNames.contains("<init>"),
            "Constant pool must contain Utf8 '<init>': " + methodNames);
        assertTrue(methodNames.contains("greet"),
            "Constant pool must contain Utf8 'greet': " + methodNames);
    }
}
