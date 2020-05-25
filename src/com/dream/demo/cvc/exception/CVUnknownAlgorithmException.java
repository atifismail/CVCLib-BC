package com.dream.demo.cvc.exception;


/**
 * Something is wrong with certificate date
 *
 */
public class CVUnknownAlgorithmException extends CVBaseException
{
	static final long serialVersionUID = 1;

	/**
	 * @brief constructor
	 *
	 */
	public CVUnknownAlgorithmException()
	{
		super("res:com.secunet.cvca.exception.CVUnknownAlgorithmException");
	}
}
