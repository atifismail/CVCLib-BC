package com.dream.demo.cvc.exception;


/**
 * decode error exception
 * @author meier.marcus
 *
 */
public class CVDecodeErrorException extends CVBaseException {
	static final long serialVersionUID = 1;
	/**
	 * @brief constructor
	 *
	 */
	public CVDecodeErrorException()
	{
		super("res:com.secunet.cvca.exception.CVDecodeErrorException");
	}
}
