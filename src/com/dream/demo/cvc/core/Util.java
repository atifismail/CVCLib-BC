package com.dream.demo.cvc.core;

import java.io.File;

import org.bouncycastle.asn1.DERBitString;


/**
 * Just a small helper class with some small static methods
 * @author meier.marcus
 *
 */
public class Util {
	
	/**
	 * Loads CV certificate from file.
	 * 
	 * @param certificateFile
	 *            Certificate file.
	 * @return CV certificate.
	 */
	public static CVCertificate loadCVCertificate(File certificateFile)
	{
		CVCertificate result = null;

		if (certificateFile == null)
		{
			return null;
		}

		if (!certificateFile.exists())
		{
			System.out.println("File does not exist: " + certificateFile.getAbsolutePath());
			return null;
		}

		try
		{
			DataBuffer rawCert = DataBuffer.readFromFile(certificateFile.getAbsolutePath());
			result = new CVCertificate(rawCert);
			System.out.println("Loaded " + result.getCertHolderRef() + " from " + certificateFile.getAbsolutePath());
		}
		catch (Exception e)
		{
			System.out.println("Unable to read CV certificate from file:" + e.getMessage());
			result = null;
		}

		return result;
	}
	
	public static void printCVCertificate(File certificateFile)
	{
		CVCertificate result = null;

		if (certificateFile == null)
		{
			System.out.println("File does not exist: " + certificateFile.getAbsolutePath());
			return;
		}

		if (!certificateFile.exists())
		{
			System.out.println("File does not exist: " + certificateFile.getAbsolutePath());
			return;
		}

		try
		{
			DataBuffer rawCert = DataBuffer.readFromFile(certificateFile.getAbsolutePath());
			result = new CVCertificate(rawCert);
			StringBuilder sb = new StringBuilder();			
			sb.append("Certificate Body\n");
			sb.append("\tProfile Identifier: " + result.getProfileId() + "\n");
			sb.append("\tAuthority Reference: " + result.getCertAuthRef()+ "\n");
			sb.append("\tPublic Key...." + "\n");
			sb.append("\t\tHash Code: " + result.getPublicKey().hashCode()+ "\n");
			sb.append("\t\tKey Length: " + result.getPublicKey().getKeyLength()+ "\n");
			sb.append("\t\tKey Algorithm: " + result.getPublicKey().getAlgorithm()+ "\n");			
			sb.append("\tHolder Reference: " + result.getCertHolderRef()+ "\n");
			sb.append("\tHolder Authorization Template: " + result.getCertHolderAuth().genHolderAuth().asHex("")+ "\n");
			sb.append("\tEffective Date: " + result.getEffDate().getDate().toString()+ "\n");
			sb.append("\tExpiry Date: " + result.getExpDate().getDate().toString()+ "\n");
			sb.append("Signature: " + result.getSignature().asHex("")+ "\n");	
			System.out.println(sb.toString());
		}
		catch (Exception e)
		{
			System.out.println("Unable to read CV certificate from file:" + e.getMessage());
			result = null;
		}

		
	}

	/**
	 * This method removes leading zeros of an byte array
	 * @param in
	 * @return
	 */
	public static byte[] removeLeadingZeros(byte[] in)
	{
		if(in.length > 1)
		{
			DataBuffer buffer = new DataBuffer();
			int i = 0;
			while(in[i] == 0x00)
			{
				i++;
			}

			while(i < in.length)
			{
				buffer.append(in[i]);
				i++;
			}
			return buffer.toByteArray();
		}
		return in;
	}

	public static boolean[] bitStringToBoolean(DERBitString bitString)
    {
        if (bitString != null)
        {
            byte[]          bytes = bitString.getBytes();
            boolean[]       boolId = new boolean[bytes.length * 8 - bitString.getPadBits()];

            for (int i = 0; i != boolId.length; i++)
            {
                boolId[i] = (bytes[i / 8] & (0x80 >>> (i % 8))) != 0;
            }

            return boolId;
        }

        return null;
    }

	public static DERBitString booleanToBitString(boolean[] id)
    {
        byte[] bytes = new byte[(id.length + 7) / 8];

        for (int i = 0; i != id.length; i++)
        {
            bytes[i / 8] |= (id[i]) ? (1 << ((7 - (i % 8)))) : 0;
        }

        int pad = id.length % 8;

        if (pad == 0)
        {
            return new DERBitString(bytes);
        }
        else
        {
            return new DERBitString(bytes, 8 - pad);
        }
    }
}
