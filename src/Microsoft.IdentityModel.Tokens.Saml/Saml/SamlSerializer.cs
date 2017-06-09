//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Globalization;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    /// <summary>
    /// Reads and writes Saml Assertions and tokens
    /// </summary>
    public class SamlSerializer
    {
#pragma warning disable 1591

        /// <summary>
        /// Instaniates a new instance of <see cref="SamlSerializer"/>.
        /// </summary>
        public SamlSerializer()
        {
        }

        /// <summary>
        /// Read the &lt;saml:Action> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlDictionaryReader"/> positioned at a <see cref="SamlAction"/> element.</param>
        /// <returns>A <see cref="SamlAction"/> instance.</returns>
        protected virtual SamlAction ReadAction(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, SamlConstants.Elements.Action, SamlConstants.Namespace);

            try
            {
                // @xsi:type
                XmlUtil.ValidateXsiType(reader, SamlConstants.Types.ActionType, SamlConstants.Namespace);

                // @Namespace - optional. If this element is absent, the default namespace is in effect.
                // @attributes
                string namespaceValue = reader.GetAttribute(SamlConstants.Attributes.Namespace);
                if (string.IsNullOrEmpty(namespaceValue))
                {
                    if (!CanCreateValidUri(namespaceValue, UriKind.Absolute))
                        throw LogReadException(LogMessages.IDX11111, SamlConstants.Elements.Action, SamlConstants.Attributes.Namespace, namespaceValue);
                }
                else
                {
                    namespaceValue = SamlConstants.DefaultActionNamespace;
                }

                var action = reader.ReadElementContentAsString();
                reader.MoveToContent();
                return new SamlAction(action, new Uri(namespaceValue));
            }
            catch (Exception ex)
            {
                if (ex is SamlSecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11112, ex, SamlConstants.Elements.Action, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:Advice> element.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The Advice element has an extensibility point to allow XML elements
        /// from non-SAML namespaces to be included. By default, because the 
        /// Advice may be ignored without affecting the semantics of the 
        /// assertion, any such elements are ignored. To handle the processing
        /// of those elements, override this method.
        /// </para>
        /// </remarks>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="SamlAdvice"/> element.</param>
        /// <returns>A <see cref="SamlAdvice"/> instance.</returns>
        protected virtual SamlAdvice ReadAdvice(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, SamlConstants.Elements.Advice, SamlConstants.Namespace);
            try
            {
                SamlAdvice advice = new SamlAdvice();
                bool isEmpty = reader.IsEmptyElement;

                // @xsi:type
                XmlUtil.ValidateXsiType(reader, SamlConstants.Types.AdviceType, SamlConstants.Namespace);

                reader.Read();
                if (!isEmpty)
                {
                    // <AssertionIDRef|Assertion> 0-OO
                    while (reader.IsStartElement())
                    {
                        // <AssertionIDRef>, <Assertion>
                        if (reader.IsStartElement(SamlConstants.Elements.AssertionIdReference, SamlConstants.Namespace))
                            advice.AssertionIdReferences.Add(ReadSimpleNCNameElement(reader, SamlConstants.Elements.AssertionIdReference));
                        else if (reader.IsStartElement(SamlConstants.Elements.Assertion, SamlConstants.Namespace))
                            advice.Assertions.Add(ReadAssertion(reader));
                        else
                            reader.Skip();
                    }

                    reader.ReadEndElement();
                }

                return advice;
            }
            catch (Exception ex)
            {
                if (ex is SamlSecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11112, ex, SamlConstants.Elements.Advice, ex);
            }
        }

        /// <summary>
        /// Reads a &lt;saml:Assertion> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="SamlAssertion"/> element.</param>
        /// <returns>A <see cref="SamlAssertion"/> instance.</returns>
        public virtual SamlAssertion ReadAssertion(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, SamlConstants.Elements.Assertion, SamlConstants.Namespace);

            var envelopeReader = new EnvelopedSignatureReader(XmlDictionaryReader.CreateDictionaryReader(reader));
            var assertion = new SamlAssertion();

            // TODO - handle EncryptedAssertions
            // If it's an EncryptedAssertion, we need to retrieve the plaintext
            // and repoint our reader
            //if (reader.IsStartElement(Saml2Constants.Elements.EncryptedAssertion, Saml2Constants.Namespace))
            //{
            //    EncryptingCredentials encryptingCredentials = null;
            //    //plaintextReader = CreatePlaintextReaderFromEncryptedData(
            //    //                    plaintextReader,
            //    //                    out encryptingCredentials);

            //    assertion.EncryptingCredentials = encryptingCredentials;
            //}

            try
            {
                // @xsi:type
                XmlUtil.ValidateXsiType(envelopeReader, SamlConstants.Types.AssertionType, SamlConstants.Namespace);

                // @MajorVersion - required - must be "1"
                string majorVersion = envelopeReader.GetAttribute(SamlConstants.Attributes.MajorVersion);
                if (string.IsNullOrEmpty(majorVersion))
                    throw LogReadException(LogMessages.IDX11115, SamlConstants.Elements.Assertion, SamlConstants.Attributes.MajorVersion);

                if (!StringComparer.Ordinal.Equals(SamlConstants.MajorVersionValue.ToString(), majorVersion))
                    throw LogReadException(LogMessages.IDX11116, majorVersion);

                // @MinorVersion - required - must be "1"
                string minorVersion = envelopeReader.GetAttribute(SamlConstants.Attributes.MinorVersion);
                if (string.IsNullOrEmpty(minorVersion))
                    throw LogReadException(LogMessages.IDX11115, SamlConstants.Elements.Assertion, SamlConstants.Attributes.MinorVersion);

                if (!StringComparer.Ordinal.Equals(SamlConstants.MinorVersionValue.ToString(), minorVersion))
                    throw LogReadException(LogMessages.IDX11117, minorVersion);

                // @ID - required
                string value = envelopeReader.GetAttribute(SamlConstants.Attributes.AssertionId);
                if (string.IsNullOrEmpty(value))
                    throw LogReadException(LogMessages.IDX11115, SamlConstants.Elements.Assertion, SamlConstants.Attributes.AssertionId);
                assertion.AssertionId = value;

                // @Issuer - required
                value = envelopeReader.GetAttribute(SamlConstants.Attributes.Issuer);
                if (string.IsNullOrEmpty(value))
                    throw LogReadException(LogMessages.IDX11115, SamlConstants.Elements.Assertion, SamlConstants.Attributes.Issuer);
                assertion.Issuer = value;

                // @IssueInstant - required
                value = envelopeReader.GetAttribute(SamlConstants.Attributes.IssueInstant);
                if (string.IsNullOrEmpty(value))
                    throw LogReadException(LogMessages.IDX11115, SamlConstants.Elements.Assertion, SamlConstants.Attributes.IssueInstant);
                assertion.IssueInstant = XmlConvert.ToDateTime(value, XmlDateTimeSerializationMode.Utc);

                // <Conditions> 0-1
                if (envelopeReader.IsStartElement(SamlConstants.Elements.Conditions, SamlConstants.Namespace))
                    assertion.Conditions = ReadConditions(envelopeReader);

                // <Advice> 0-1
                if (envelopeReader.IsStartElement(SamlConstants.Elements.Advice, SamlConstants.Namespace))
                    assertion.Advice = ReadAdvice(envelopeReader);

                // <Subject> 0-1
                //if (envelopeReader.IsStartElement(SamlConstants.Elements.subject, Saml2Constants.Namespace))
                //    assertion.Subject = ReadSubject(envelopeReader);             

                // <Statement|AuthenticationStatement|AuthorizationDecisionStatement|AttributeStatement>, 0-OO
                while (envelopeReader.IsStartElement())
                {
                    SamlStatement statement;

                    //if (envelopeReader.IsStartElement(SamlConstants.Elements.Statement, SamlConstants.Namespace))
                    //    statement = ReadStatement(envelopeReader);
                    if (envelopeReader.IsStartElement(SamlConstants.Elements.AttributeStatement, SamlConstants.Namespace))
                        statement = ReadAttributeStatement(envelopeReader);
                    else if (envelopeReader.IsStartElement(SamlConstants.Elements.AuthenticationStatement, SamlConstants.Namespace))
                        statement = ReadAuthenticationStatement(envelopeReader);
                    else if (envelopeReader.IsStartElement(SamlConstants.Elements.AuthorizationDecisionStatement, SamlConstants.Namespace))
                        statement = ReadAuthorizationDecisionStatement(envelopeReader);
                    else
                        break;

                    assertion.Statements.Add(statement);
                }

                envelopeReader.ReadEndElement();
                //if (assertion.Subject == null)
                //{
                //    // An assertion with no statements MUST contain a <Subject> element. [Saml2Core, line 585]
                //    if (0 == assertion.Statements.Count)
                //        throw LogReadException(LogMessages.IDX11108, Saml2Constants.Elements.Assertion);

                //    // Furthermore, the built-in statement types all require the presence of a subject.
                //    // [Saml2Core, lines 1050, 1168, 1280]
                //    foreach (Saml2Statement statement in assertion.Statements)
                //    {
                //        if (statement is Saml2AuthenticationStatement
                //            || statement is Saml2AttributeStatement
                //            || statement is Saml2AuthorizationDecisionStatement)
                //        {
                //            throw LogReadException(LogMessages.IDX11109, Saml2Constants.Elements.Assertion);
                //        }
                //    }
                //}

                // attach signedXml for validation of signature
                assertion.Signature = envelopeReader.Signature;
                return assertion;
            }
            catch (Exception ex)
            {
                if (ex is SamlSecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11112, ex, SamlConstants.Elements.Assertion, ex);
            }
        }

        /// <summary>
        /// Determines whether a URI is valid and can be created using the specified UriKind.
        /// Uri.TryCreate is used here, which is more lax than Uri.IsWellFormedUriString.
        /// The reason we use this function is because IsWellFormedUriString will reject valid URIs if they are IPv6 or require escaping.
        /// </summary>
        /// <param name="uriString">The string to check.</param>
        /// <param name="uriKind">The type of URI (usually UriKind.Absolute)</param>
        /// <returns>True if the URI is valid, false otherwise.</returns>
        internal static bool CanCreateValidUri(string uriString, UriKind uriKind)
        {
            Uri tempUri;
            return Uri.TryCreate(uriString, uriKind, out tempUri);
        }

        internal static Exception LogReadException(string format, params object[] args)
        {
            return LogHelper.LogExceptionMessage(new SamlSecurityTokenReadException(LogHelper.FormatInvariant(format, args)));
        }

        internal static string ReadSimpleNCNameElement(XmlDictionaryReader reader, string name)
        {
            try
            {
                if (reader.IsEmptyElement)
                    throw LogReadException(LogMessages.IDX11114, name);

                XmlUtil.ValidateXsiType(reader, XmlSignatureConstants.Attributes.NcName, XmlSignatureConstants.XmlSchemaNamespace);

                reader.MoveToElement();
                return reader.ReadElementContentAsString();
            }
            catch (Exception ex)
            {
                throw LogReadException(LogMessages.IDX11112, ex, SamlConstants.Elements.AssertionIdReference, ex);
            }
        }

        //protected virtual SamlAdvice ReadAdvice(XmlDictionaryReader reader)
        //{
        //    if (reader == null)
        //        throw LogHelper.LogArgumentNullException(nameof(reader));

        //    var advice = new SamlAdvice();

        //    // SAML Advice is an optional element and all its child elements are optional
        //    // too. So we may have an empty saml:Advice element in the saml token.
        //    if (reader.IsEmptyElement)
        //    {
        //        // Just issue a read for the empty element.
        //        reader.MoveToContent();
        //        reader.Read();
        //        return advice;
        //    }

        //    reader.MoveToContent();
        //    reader.Read();
        //    while (reader.IsStartElement())
        //    {
        //        if (reader.IsStartElement(SamlConstants.Elements.AssertionIdReference, SamlConstants.Namespace))
        //            advice.AssertionIdReferences.Add(reader.ReadElementContentAsString());
        //        else if (reader.IsStartElement(SamlConstants.Elements.Assertion, SamlConstants.Namespace))
        //            advice.Assertions.Add(ReadAssertion(reader));
        //        else
        //            throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLBadSchema"));
        //    }

        //    reader.MoveToContent();
        //    reader.ReadEndElement();
        //    return advice;
        //}

        //public virtual SamlAssertion ReadAssertion(XmlDictionaryReader reader)
        //{
        //    XmlUtil.CheckReaderOnEntry(reader, SamlConstants.Elements.Assertion, SamlConstants.Namespace);

        //    SamlAssertion assertion = new SamlAssertion();

        //    string attributeValue = reader.GetAttribute(SamlConstants.Attributes.MajorVersion, null);
        //    if (string.IsNullOrEmpty(attributeValue))
        //        throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLAssertionMissingMajorVersionAttributeOnRead"));

        //    // TODO - use convert?
        //    int majorVersion = int.Parse(attributeValue, CultureInfo.InvariantCulture);
        //    attributeValue = reader.GetAttribute(SamlConstants.Attributes.MinorVersion, null);
        //    if (string.IsNullOrEmpty(attributeValue))
        //        throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLAssertionMissingMinorVersionAttributeOnRead"));

        //    // TODO - use convert?
        //    int minorVersion = int.Parse(attributeValue, CultureInfo.InvariantCulture);
        //    if ((majorVersion != SamlConstants.MajorVersionValue) || (minorVersion != SamlConstants.MinorVersionValue))
        //        throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLTokenVersionNotSupported, majorVersion, minorVersion, SamlConstants.MajorVersion, SamlConstants.MinorVersionValue"));

        //    attributeValue = reader.GetAttribute(SamlConstants.Attributes.AssertionId, null);
        //    if (string.IsNullOrEmpty(attributeValue))
        //        throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLAssertionIdRequired"));

        //    if (!IsAssertionIdValid(attributeValue))
        //        throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLAssertionIDIsInvalid, attributeValue"));

        //    assertion.AssertionId = attributeValue;

        //    attributeValue = reader.GetAttribute(SamlConstants.Attributes.Issuer, null);
        //    if (string.IsNullOrEmpty(attributeValue))
        //        throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLAssertionMissingIssuerAttributeOnRead"));

        //    assertion.Issuer = attributeValue;

        //    attributeValue = reader.GetAttribute(SamlConstants.Attributes.IssueInstant, null);
        //    // TODO - try/catch throw SamlReadException
        //    if (!string.IsNullOrEmpty(attributeValue))
        //        assertion.IssueInstant = DateTime.ParseExact(
        //            attributeValue, SamlConstants.AcceptedDateTimeFormats, DateTimeFormatInfo.InvariantInfo, DateTimeStyles.None).ToUniversalTime();

        //    reader.MoveToContent();
        //    reader.Read();

        //    if (reader.IsStartElement(SamlConstants.Elements.Conditions, SamlConstants.Namespace))
        //    {

        //        var conditions = ReadConditions(reader);
        //        if (conditions == null)
        //            throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLUnableToLoadCondtions"));

        //        assertion.Conditions = conditions;
        //    }

        //    if (reader.IsStartElement(SamlConstants.Elements.Advice, SamlConstants.Namespace))
        //    {
        //        var advice = ReadAdvice(reader);
        //        if (advice == null)
        //            throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLUnableToLoadAdvice"));

        //        assertion.Advice = advice;
        //    }

        //    while (reader.IsStartElement())
        //    {
        //        if (reader.IsStartElement(XmlSignatureConstants.Elements.Signature, XmlSignatureConstants.Namespace))
        //        {
        //            reader.Skip();
        //        }
        //        else
        //        {
        //            SamlStatement statement = ReadStatement(reader);
        //            if (statement == null)
        //                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLUnableToLoadStatement"));

        //            assertion.Statements.Add(statement);
        //        }
        //    }

        //    if (assertion.Statements.Count == 0)
        //        throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLAssertionRequireOneStatementOnRead"));

        //    //if (wrappedReader.IsStartElement(samlSerializer.DictionaryManager.XmlSignatureDictionary.Signature, samlSerializer.DictionaryManager.XmlSignatureDictionary.Namespace))
        //    //    this.ReadSignature(wrappedReader, samlSerializer);

        //    reader.MoveToContent();
        //    reader.ReadEndElement();

        //    // set as property on assertion
        //    //this.tokenStream = wrappedReader.XmlTokens;

        //    return assertion;
        //}

        /// <summary>
        /// Reads the &lt;saml:Attribute> element.
        /// </summary>
        /// <remarks>
        /// The default implementation requires that the content of the
        /// Attribute element be a simple string. To handle complex content
        /// or content of declared simple types other than xs:string, override
        /// this method.
        /// </remarks>
        /// <param name="reader">An <see cref="XmlReader"/> positioned at a <see cref="SamlAttribute"/> element.</param>
        /// <returns>A <see cref="SamlAttribute"/> instance.</returns>
        public virtual SamlAttribute ReadAttribute(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            SamlAttribute attribute = new SamlAttribute();

            var name = reader.GetAttribute(SamlConstants.Attributes.AttributeName, null);
            if (string.IsNullOrEmpty(name))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAttributeMissingNameAttributeOnRead"));

            var nameSpace = reader.GetAttribute(SamlConstants.Attributes.AttributeNamespace, null);
            if (string.IsNullOrEmpty(nameSpace))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAttributeMissingNamespaceAttributeOnRead"));

            // TODO is this the right thing?
            var claimType = string.IsNullOrEmpty(nameSpace) ? name : nameSpace + "/" + name;

            reader.MoveToContent();
            reader.Read();
            while (reader.IsStartElement(SamlConstants.Elements.AttributeValue, SamlConstants.Namespace))
            {
                // We will load all Attributes as a string value by default.
                attribute.AttributeValues.Add(reader.ReadElementContentAsString());
            }

            if (attribute.AttributeValues.Count == 0)
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("SAMLAttributeShouldHaveOneValue"));

            reader.MoveToContent();
            reader.ReadEndElement();

            return attribute;
        }

        /// <summary>
        /// Reads the &lt;saml:AttributeStatement> element, or a
        /// &lt;saml:Statement element that specifies an xsi:type of
        /// saml:AttributeStatementType.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="SamlAttributeStatement"/> element.</param>
        /// <returns>A <see cref="SamlAttributeStatement"/> instance.</returns>
        protected virtual SamlAttributeStatement ReadAttributeStatement(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, SamlConstants.Elements.Subject, SamlConstants.Namespace);

            if (!reader.IsStartElement(SamlConstants.Elements.Subject, SamlConstants.Namespace))
                throw LogReadException(LogMessages.IDX11119, SamlConstants.Elements.AttributeStatement, SamlConstants.Elements.Subject, SamlConstants.Elements.Assertion);
            var statement = new SamlAttributeStatement();
            statement.Subject = ReadSubject(reader);
            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(SamlConstants.Elements.Attribute, SamlConstants.Namespace))
                {
                    SamlAttribute attribute = ReadAttribute(reader);
                    if (attribute == null)
                        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLUnableToLoadAttribute"));

                    statement.Attributes.Add(attribute);
                }
                else
                {
                    break;
                }
            }

            if (statement.Attributes.Count == 0)
            {
                // Each Attribute statement should have at least one attribute.
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAttributeStatementMissingAttributeOnRead"));
            }

            reader.MoveToContent();
            reader.ReadEndElement();

            return statement;
        }

        ///// <summary>
        ///// Read saml:AudienceRestrictionCondition from the given XmlReader.
        ///// </summary>
        ///// <param name="reader">XmlReader positioned at a saml:AudienceRestrictionCondition.</param>
        ///// <returns>SamlAudienceRestrictionCondition</returns>
        ///// <exception cref="ArgumentNullException">The inpur parameter 'reader' is null.</exception>
        ///// <exception cref="XmlException">The XmlReader is not positioned at saml:AudienceRestrictionCondition.</exception>
        ///// <summary>
        ///// Reads an attribute value.
        ///// </summary>
        ///// <param name="reader">XmlReader to read from.</param>
        ///// <param name="attribute">The current attribute that is being read.</param>
        ///// <returns>The attribute value as a string.</returns>
        ///// <exception cref="ArgumentNullException">The input parameter 'reader' is null.</exception>
        //protected virtual string ReadAttributeValue(XmlDictionaryReader reader, SamlAttribute attribute)
        //{
        //    // This code was designed realizing that the writter of the xml controls how our
        //    // reader will report the NodeType. A completely differnet system could write the values.
        //    // Considering NodeType is important, because we need to read the entire value, end element and not loose anything significant.
        //    //
        //    // Couple of cases to help understand the design choices.
        //    //
        //    // 1.
        //    // "<MyElement xmlns=""urn:mynamespace""><another>complex</another></MyElement><sibling>value</sibling>"
        //    // Could result in the our reader reporting the NodeType as Text OR Element, depending if '<' was entitized to '&lt;'
        //    //
        //    // 2.
        //    // " <MyElement xmlns=""urn:mynamespace""><another>complex</another></MyElement><sibling>value</sibling>"
        //    // Could result in the our reader reporting the NodeType as Text OR Whitespace.  Post Whitespace processing, the NodeType could be
        //    // reported as Text or Element, depending if '<' was entitized to '&lt;'
        //    //
        //    // 3.
        //    // "/r/n/t   "
        //    // Could result in the our reader reporting the NodeType as whitespace.
        //    //
        //    // Since an AttributeValue with ONLY Whitespace and a complex Element proceeded by whitespace are reported as the same NodeType (2. and 3.)
        //    // the whitespace is remembered and discarded if an found is found, otherwise it becomes the value. This is to help users who accidently put a space when adding claims in ADFS
        //    // If we just skipped the Whitespace, then an AttributeValue that started with Whitespace would loose that part and claims generated from the AttributeValue
        //    // would be missing that part.
        //    //

        //    if (reader == null)
        //        throw LogHelper.LogArgumentNullException(nameof(reader));

        //    string result = string.Empty;
        //    string whiteSpace = string.Empty;

        //    reader.ReadStartElement(SamlConstants.Elements.AttributeValue, SamlConstants.Namespace);

        //    while (reader.NodeType == XmlNodeType.Whitespace)
        //    {
        //        whiteSpace += reader.Value;
        //        reader.Read();
        //    }

        //    reader.MoveToContent();
        //    if (reader.NodeType == XmlNodeType.Element)
        //    {
        //        while (reader.NodeType == XmlNodeType.Element)
        //        {
        //            result += reader.ReadOuterXml();
        //            reader.MoveToContent();
        //        }
        //    }
        //    else
        //    {
        //        result = whiteSpace;
        //        result += reader.ReadContentAsString();
        //    }

        //    reader.ReadEndElement();
        //    return result;
        //}

        /// <summary>
        /// 
        /// </summary>
        /// <param name="reader"></param>
        /// <returns></returns>
        protected virtual SamlAudienceRestrictionCondition ReadAudienceRestrictionCondition(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, SamlConstants.Elements.AudienceRestrictionCondition, SamlConstants.Namespace);

            reader.ReadStartElement();
            var audienceRestrictionCondition = new SamlAudienceRestrictionCondition();
            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(SamlConstants.Elements.Audience, SamlConstants.Namespace))
                {
                    string audience = reader.ReadElementContentAsString();
                    if (string.IsNullOrEmpty(audience))
                        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("ID4083"));

                    audienceRestrictionCondition.Audiences.Add(new Uri(audience, UriKind.RelativeOrAbsolute));
                }
                else
                {
                    throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SamlConstants.ElementNames.Audience, SamlConstants.Namespace, reader.LocalName, reader.NamespaceURI"));
                }
            }

            if (audienceRestrictionCondition.Audiences.Count == 0)
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("ID4084"));

            reader.MoveToContent();
            reader.ReadEndElement();

            return audienceRestrictionCondition;
        }

        /// <summary>
        /// Read the saml:AuthenticationStatement.
        /// </summary>
        /// <param name="reader">XmlReader positioned at a saml:AuthenticationStatement.</param>
        /// <returns>SamlAuthenticationStatement</returns>
        /// <exception cref="ArgumentNullException">The input parameter 'reader' is null.
        /// or the statement contains a unknown child element.</exception>
        protected virtual SamlAuthenticationStatement ReadAuthenticationStatement(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            var authenticationStatement = new SamlAuthenticationStatement();

            string authInstance = reader.GetAttribute(SamlConstants.Attributes.AuthenticationInstant, null);
            if (string.IsNullOrEmpty(authInstance))
                throw LogReadException(LogMessages.IDX11115, SamlConstants.Elements.AuthenticationStatement, SamlConstants.Attributes.AuthenticationInstant);

            var authenticationInstant = DateTime.ParseExact(
                authInstance, SamlConstants.AcceptedDateTimeFormats, DateTimeFormatInfo.InvariantInfo, DateTimeStyles.None).ToUniversalTime();

            var authenticationMethod = reader.GetAttribute(SamlConstants.Attributes.AuthenticationMethod, null);
            if (string.IsNullOrEmpty(authenticationMethod))
                throw LogReadException(LogMessages.IDX11115, SamlConstants.Elements.AuthenticationStatement, SamlConstants.Attributes.AuthenticationMethod);

            authenticationStatement.Subject = ReadSubject(reader);
            if (reader.IsStartElement(SamlConstants.Elements.SubjectLocality, SamlConstants.Namespace))
            {
                var dnsAddress = reader.GetAttribute(SamlConstants.Elements.SubjectLocalityDNSAddress, null);
                var ipAddress = reader.GetAttribute(SamlConstants.Elements.SubjectLocalityIPAddress, null);

                if (reader.IsEmptyElement)
                {
                    reader.MoveToContent();
                    reader.Read();
                }
                else
                {
                    reader.MoveToContent();
                    reader.Read();
                    reader.ReadEndElement();
                }
            }

            while (reader.IsStartElement())
            {
                authenticationStatement.AuthorityBindings.Add(ReadAuthorityBinding(reader));
            }

            reader.MoveToContent();
            reader.ReadEndElement();

            return authenticationStatement;
        }

        protected virtual SamlAuthorityBinding ReadAuthorityBinding(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, SamlConstants.Elements.AuthorityBinding, SamlConstants.Namespace);

            string authKind = reader.GetAttribute(SamlConstants.Attributes.AuthorityKind, null);
            if (string.IsNullOrEmpty(authKind))
                throw XmlUtil.LogAttributeMissingReadException(SamlConstants.Elements.AuthorityBinding, SamlConstants.Attributes.AuthorityKind);

            string[] authKindParts = authKind.Split(':');
            if (authKindParts.Length > 2)
                throw XmlUtil.LogReadException(LogMessages.IDX11108, authKind);

            string localName;
            string prefix;
            string nameSpace;
            if (authKindParts.Length == 2)
            {
                prefix = authKindParts[0];
                localName = authKindParts[1];
            }
            else
            {
                prefix = string.Empty;
                localName = authKindParts[0];
            }

            nameSpace = reader.LookupNamespace(prefix);
            var authorityKind = new XmlQualifiedName(localName, nameSpace);

            var binding = reader.GetAttribute(SamlConstants.Attributes.Binding, null);
            if (string.IsNullOrEmpty(binding))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthorityBindingMissingBindingOnRead"));

            var location = reader.GetAttribute(SamlConstants.Attributes.Location, null);
            if (string.IsNullOrEmpty(location))
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAuthorityBindingMissingLocationOnRead"));

            if (reader.IsEmptyElement)
            {
                reader.MoveToContent();
                reader.Read();
            }
            else
            {
                reader.MoveToContent();
                reader.Read();
                reader.ReadEndElement();
            }

            return new SamlAuthorityBinding(authorityKind, binding, location);
        }

        protected virtual SamlAuthorizationDecisionStatement ReadAuthorizationDecisionStatement(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            var statement = new SamlAuthorizationDecisionStatement();

            var resource = reader.GetAttribute(SamlConstants.Attributes.Resource, null);
            if (string.IsNullOrEmpty(resource))
                throw LogReadException(LogMessages.IDX11115, SamlConstants.Elements.AuthorizationDecisionStatement, SamlConstants.Attributes.Resource);

            string decisionString = reader.GetAttribute(SamlConstants.Attributes.Decision, null);
            if (string.IsNullOrEmpty(decisionString))
                throw LogReadException(LogMessages.IDX11115, SamlConstants.Elements.AuthorizationDecisionStatement, SamlConstants.Attributes.Decision);

            if (decisionString.Equals(SamlAccessDecision.Deny.ToString(), StringComparison.OrdinalIgnoreCase))
                statement.AccessDecision = SamlAccessDecision.Deny;
            else if (decisionString.Equals(SamlAccessDecision.Permit.ToString(), StringComparison.OrdinalIgnoreCase))
                statement.AccessDecision = SamlAccessDecision.Permit;
            else
                statement.AccessDecision = SamlAccessDecision.Indeterminate;

            reader.MoveToContent();
            reader.Read();

            if (!reader.IsStartElement(SamlConstants.Elements.Subject, SamlConstants.Namespace))
                throw LogReadException(LogMessages.IDX11119, SamlConstants.Elements.AuthorizationDecisionStatement, SamlConstants.Elements.Subject, SamlConstants.Elements.Assertion);

            statement.Subject = ReadSubject(reader);
            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(SamlConstants.Elements.Action, SamlConstants.Namespace))
                {
                    statement.Actions.Add(ReadAction(reader));
                }
                else if (reader.IsStartElement(SamlConstants.Elements.Evidence, SamlConstants.Namespace))
                {
                    if (statement.Evidence != null)
                        throw XmlUtil.LogReadException(LogMessages.IDX11100, SamlConstants.Elements.Evidence);

                    statement.Evidence = ReadEvidence(reader);
                }
                else
                    throw XmlUtil.LogUnknownElementReadException(SamlConstants.Elements.Subject, reader.Name);
            }

            if (statement.Actions.Count == 0)
                throw XmlUtil.LogReadException(LogMessages.IDX11102);

            reader.MoveToContent();
            reader.ReadEndElement();

            return statement;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="reader"></param>
        /// <returns></returns>
        protected virtual SamlCondition ReadCondition(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (reader.IsStartElement(SamlConstants.Elements.AudienceRestrictionCondition, SamlConstants.Namespace))
            {
                return ReadAudienceRestrictionCondition(reader);
            }
            else if (reader.IsStartElement(SamlConstants.Elements.DoNotCacheCondition, SamlConstants.Namespace))
            {
                return ReadDoNotCacheCondition(reader);
            }
            else
                throw LogReadException(LogMessages.IDX11118, reader.Name);
        }

        /// <summary>
        /// Reads the &lt;saml:Conditions> element.
        /// </summary>
        /// <remarks>
        /// To handle custom &lt;saml:Condition> elements, override this
        /// method.
        /// </remarks>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="SamlConditions"/> element.</param>
        /// <returns>A <see cref="SamlConditions"/> instance.</returns>
        protected virtual SamlConditions ReadConditions(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            //var conditions = new SamlConditions();
            var nbf = DateTimeUtil.GetMinValue(DateTimeKind.Utc);
            string time = reader.GetAttribute(SamlConstants.Attributes.NotBefore, null);
            if (!string.IsNullOrEmpty(time))
                nbf = DateTime.ParseExact(time, SamlConstants.AcceptedDateTimeFormats, DateTimeFormatInfo.InvariantInfo, DateTimeStyles.None).ToUniversalTime();

            var notOnOrAfter = DateTimeUtil.GetMaxValue(DateTimeKind.Utc);
            time = reader.GetAttribute(SamlConstants.Attributes.NotOnOrAfter, null);
            if (!string.IsNullOrEmpty(time))
                notOnOrAfter = DateTime.ParseExact(time, SamlConstants.AcceptedDateTimeFormats, DateTimeFormatInfo.InvariantInfo, DateTimeStyles.None).ToUniversalTime();

            var conditions = new SamlConditions(nbf, notOnOrAfter);
            // Saml Conditions element is an optional element and all its child element
            // are optional as well. So we can have a empty <saml:Conditions /> element
            // in a valid Saml token.
            if (reader.IsEmptyElement)
            {
                // Just issue a read to read the Empty element.
                reader.MoveToContent();
                reader.Read();
                return conditions;
            }

            reader.ReadStartElement();
            while (reader.IsStartElement())
            {
                conditions.Conditions.Add(ReadCondition(reader));
            }

            reader.ReadEndElement();

            return conditions;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="reader"></param>
        /// <returns></returns>
        protected virtual SamlDoNotCacheCondition ReadDoNotCacheCondition(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, SamlConstants.Elements.DoNotCacheCondition, SamlConstants.Namespace);

            // TODO what is this about
            // saml:DoNotCacheCondition is a empty element. So just issue a read for
            // the empty element.
            if (reader.IsEmptyElement)
            {
                reader.MoveToContent();
                reader.Read();
                return new SamlDoNotCacheCondition();
            }

            reader.MoveToContent();
            reader.Read();
            reader.ReadEndElement();

            return new SamlDoNotCacheCondition();
        }

        //protected virtual SamlEvidence ReadEvidence(XmlDictionaryReader reader)
        //{
        //    if (reader == null)
        //        throw LogHelper.LogArgumentNullException(nameof(reader));

        //    var evidence = new SamlEvidence();

        //    reader.MoveToContent();
        //    reader.Read();
        //    while (reader.IsStartElement())
        //    {
        //        if (reader.IsStartElement(SamlConstants.Elements.AssertionIdReference, SamlConstants.Namespace))
        //            evidence.AssertionIdReferences.Add(reader.ReadElementContentAsString());
        //        else if (reader.IsStartElement(SamlConstants.Elements.Assertion, SamlConstants.Namespace))
        //            evidence.Assertions.Add(ReadAssertion(reader));
        //         else
        //            throw XmlUtil.LogUnknownElementReadException(SamlConstants.Elements.Evidence, reader.Name);
        //    }

        //    if ((evidence.AssertionIdReferences.Count == 0) && (evidence.Assertions.Count == 0))
        //        throw XmlUtil.LogReadException(LogMessages.IDX11103);

        //    reader.MoveToContent();
        //    reader.ReadEndElement();

        //    return evidence;
        //}

        /// <summary>
        /// Reads the &lt;saml:Statement> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2Statement"/> element.</param>
        /// <returns>An instance of <see cref="Saml2Statement"/> derived type.</returns>
        /// <remarks>
        /// The default implementation only handles Statement elements which
        /// specify an xsi:type of saml:AttributeStatementType,
        /// saml:AuthnStatementType, and saml:AuthzDecisionStatementType. To
        /// handle custom statements, override this method.
        /// </remarks>
        protected virtual SamlStatement ReadStatement(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (reader.IsStartElement(SamlConstants.Elements.AuthenticationStatement, SamlConstants.Namespace))
                return ReadAuthenticationStatement(reader);
            else if (reader.IsStartElement(SamlConstants.Elements.AttributeStatement, SamlConstants.Namespace))
                return ReadAttributeStatement(reader);
            else if (reader.IsStartElement(SamlConstants.Elements.AuthorizationDecisionStatement, SamlConstants.Namespace))
                return ReadAuthorizationDecisionStatement(reader);
            else
                throw XmlUtil.LogUnknownElementReadException(SamlConstants.Elements.Assertion, reader.Name);
        }

        ///// <summary>
        ///// Read the SamlSubject from the XmlReader.
        ///// </summary>
        ///// <param name="reader">XmlReader to read the SamlSubject from.</param>
        ///// <returns>SamlSubject</returns>
        ///// <exception cref="ArgumentNullException">The input argument 'reader' is null.</exception>
        ///// <exception cref="XmlException">The reader is not positioned at a SamlSubject.</exception>
        protected virtual SamlSubject ReadSubject(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, SamlConstants.Elements.Subject, SamlConstants.Namespace);

            var subject = new SamlSubject();
            reader.Read();
            if (reader.IsStartElement(SamlConstants.Elements.NameIdentifier, SamlConstants.Namespace))
            {
                subject.NameFormat = reader.GetAttribute(SamlConstants.Attributes.NameIdentifierFormat, null);
                subject.NameQualifier = reader.GetAttribute(SamlConstants.Attributes.NameIdentifierNameQualifier, null);

                // TODO - check for empty element
                reader.MoveToContent();
                subject.Name = reader.ReadElementContentAsString();

                if (string.IsNullOrEmpty(subject.Name))
                    throw XmlUtil.LogReadException(LogMessages.IDX11104);
            }

            if (reader.IsStartElement(SamlConstants.Elements.SubjectConfirmation, SamlConstants.Namespace))
            {
                reader.MoveToContent();
                reader.Read();

                while (reader.IsStartElement(SamlConstants.Elements.SubjectConfirmationMethod, SamlConstants.Namespace))
                {
                    string method = reader.ReadElementContentAsString();
                    if (string.IsNullOrEmpty(method))
                        throw XmlUtil.LogReadException(LogMessages.IDX11105);

                    subject.ConfirmationMethods.Add(method);
                }

                if (subject.ConfirmationMethods.Count == 0)
                {
                    // A SubjectConfirmaton clause should specify at least one ConfirmationMethod.
                    throw XmlUtil.LogReadException(LogMessages.IDX11106);
                }

                if (reader.IsStartElement(SamlConstants.Elements.SubjectConfirmationData, SamlConstants.Namespace))
                {
                    // An Authentication protocol specified in the confirmation method might need this
                    // data. Just store this content value as string.
                    subject.ConfirmationData = reader.ReadElementContentAsString();
                }

                if (reader.IsStartElement(XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace))
                {
                    XmlDictionaryReader dictionaryReader = XmlDictionaryReader.CreateDictionaryReader(reader);
                    // TODO - we need to get the key
                    /// subject.Key = ReadSecurityKey(dictionaryReader);
                    //this.crypto = SamlSerializer.ResolveSecurityKey(this.securityKeyIdentifier, outOfBandTokenResolver);
                    //if (this.crypto == null)
                    //{
                    //    throw LogHelper.LogExceptionMessage(new SecurityTokenException(SR.GetString(SR.SamlUnableToExtractSubjectKey)));
                    //}
                    //this.subjectToken = SamlSerializer.ResolveSecurityToken(this.securityKeyIdentifier, outOfBandTokenResolver);
                }


                if ((subject.ConfirmationMethods.Count == 0) && (string.IsNullOrEmpty(subject.Name)))
                    throw XmlUtil.LogReadException(LogMessages.IDX11107);

                reader.MoveToContent();
                reader.ReadEndElement();
            }

            reader.MoveToContent();
            reader.ReadEndElement();

            return subject;
        }

        ///// <summary>
        ///// Read the SamlSubject KeyIdentifier from a XmlReader.
        ///// </summary>
        ///// <param name="reader">XmlReader positioned at the SamlSubject KeyIdentifier.</param>
        ///// <returns>SamlSubject Key as a SecurityKeyIdentifier.</returns>
        ///// <exception cref="ArgumentNullException">Input parameter 'reader' is null.</exception>
        ///// <exception cref="XmlException">XmlReader is not positioned at a valid SecurityKeyIdentifier.</exception>
        //protected virtual KeyInfo ReadSubjectKeyInfo(XmlDictionaryReader reader)
        //{
        //    XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace);

        //    var keyInfo = new KeyInfo();
        //    keyInfo.ReadFrom(reader);

        //    return keyInfo;
        //}

        protected virtual SamlSubjectStatement ReadSubjectStatement(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));
        }

        public virtual SamlSecurityToken ReadToken(XmlDictionaryReader reader)
        {
            var assertion = ReadAssertion(reader);

            return new SamlSecurityToken(assertion);
        }

        //protected virtual void WriteAction(XmlWriter writer, SamlAction action)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (action == null)
        //        throw LogHelper.LogArgumentNullException(nameof(action));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.Action, SamlConstants.Namespace);
        //    if (!string.IsNullOrEmpty(action.Namespace))
        //    {
        //        writer.WriteStartAttribute(SamlConstants.Attributes.ActionNamespaceAttribute, null);
        //        writer.WriteString(action.Namespace);
        //        writer.WriteEndAttribute();
        //    }

        //    writer.WriteString(action.Action);
        //    writer.WriteEndElement();
        //}

        //protected virtual void WriteAdvice(XmlWriter writer, SamlAdvice advice)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (advice == null)
        //        throw LogHelper.LogArgumentNullException(nameof(advice));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.Advice, SamlConstants.Namespace);

        //    foreach (var reference in advice.AssertionIdReferences)
        //    {
        //        writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.AssertionIdReference, SamlConstants.Namespace);
        //        writer.WriteString(reference);
        //        writer.WriteEndElement();
        //    }

        //    foreach (var assertion in advice.Assertions)
        //        WriteAssertion(writer, assertion);

        //    writer.WriteEndElement();
        //}

        //public virtual void WriteAssertion(XmlWriter writer, SamlAssertion assertion)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (assertion == null)
        //        throw LogHelper.LogArgumentNullException(nameof(assertion));

        //    if (string.IsNullOrEmpty(assertion.AssertionId))
        //        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAssertionIdRequired"));

        //    if (!IsAssertionIdValid(assertion.AssertionId))
        //        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAssertionIDIsInvalid"));

        //    if (string.IsNullOrEmpty(assertion.Issuer))
        //        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAssertionIssuerRequired"));

        //    if (assertion.Statements.Count == 0)
        //        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAssertionRequireOneStatement"));

        //    try
        //    {
        //        writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.Assertion, SamlConstants.Namespace);
        //        writer.WriteStartAttribute(SamlConstants.Attributes.MajorVersion, null);
        //        writer.WriteValue(SamlConstants.MajorVersionValue);
        //        writer.WriteEndAttribute();
        //        writer.WriteStartAttribute(SamlConstants.Attributes.MinorVersion, null);
        //        writer.WriteValue(SamlConstants.MinorVersionValue);
        //        writer.WriteEndAttribute();
        //        writer.WriteStartAttribute(SamlConstants.Attributes.AssertionId, null);
        //        writer.WriteString(assertion.AssertionId);
        //        writer.WriteEndAttribute();
        //        writer.WriteStartAttribute(SamlConstants.Attributes.Issuer, null);
        //        writer.WriteString(assertion.Issuer);
        //        writer.WriteEndAttribute();
        //        writer.WriteStartAttribute(SamlConstants.Attributes.IssueInstant, null);
        //        writer.WriteString(assertion.IssueInstant.ToString(SamlConstants.GeneratedDateTimeFormat, CultureInfo.InvariantCulture));
        //        writer.WriteEndAttribute();

        //        // Write out conditions
        //        if (assertion.Conditions != null)
        //            WriteConditions(writer, assertion.Conditions);

        //        // Write out advice if there is one
        //        if (assertion.Advice != null)
        //            WriteAdvice(writer, assertion.Advice);

        //        foreach (var statement in assertion.Statements)
        //            WriteStatement(writer, statement);

        //        writer.WriteEndElement();
        //    }
        //    catch (Exception ex)
        //    {
        //        throw LogHelper.LogExceptionMessage(new SecurityTokenException($"SAMLTokenNotSerialized, {ex}"));
        //    }
        //}

        //public virtual void WriteAttribute(XmlWriter writer, SamlAttribute attribute)

        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (attribute == null)
        //        throw LogHelper.LogArgumentNullException(nameof(attribute));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.Attribute, SamlConstants.Namespace);
        //    writer.WriteStartAttribute(SamlConstants.Attributes.AttributeName, null);
        //    writer.WriteString(attribute.Name);
        //    writer.WriteEndAttribute();
        //    writer.WriteStartAttribute(SamlConstants.Attributes.AttributeNamespace, null);
        //    writer.WriteString(attribute.Namespace);
        //    writer.WriteEndAttribute();

        //    foreach (var attributeValue in attribute.AttributeValues)
        //    {
        //        if (string.IsNullOrEmpty(attributeValue))
        //            throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SamlAttributeValueCannotBeNull"));

        //        writer.WriteElementString(SamlConstants.PreferredPrefix, SamlConstants.Elements.AttributeValue, SamlConstants.Namespace, attributeValue);
        //    }

        //    writer.WriteEndElement();
        //}

        //protected virtual void WriteAttributeStatement(XmlWriter writer, SamlAttributeStatement statement)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (statement == null)
        //        throw LogHelper.LogArgumentNullException(nameof(statement));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.AttributeStatement, SamlConstants.Namespace);

        //    WriteSubject(writer, statement.Subject);
        //    foreach (var attribute in statement.Attributes)
        //        WriteAttribute(writer, attribute);

        //    writer.WriteEndElement();
        //}

        //protected virtual void WriteAudienceRestrictionCondition(XmlWriter writer, SamlAudienceRestrictionCondition condition)
        //{
        //    if (condition == null)
        //        throw LogHelper.LogArgumentNullException(nameof(condition));

        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.AudienceRestrictionCondition, SamlConstants.Namespace);

        //    foreach (var audience in condition.Audiences)
        //    {
        //        // TODO - should we throw ?
        //        if (audience != null)
        //            writer.WriteElementString(SamlConstants.Elements.Audience, SamlConstants.Namespace, audience.AbsoluteUri);
        //    }

        //    writer.WriteEndElement();
        //}

        //protected virtual void WriteAuthenticationStatement(XmlWriter writer, SamlAuthenticationStatement statement)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (statement == null)
        //        throw LogHelper.LogArgumentNullException(nameof(statement));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.AuthenticationStatement, SamlConstants.Namespace);
        //    writer.WriteStartAttribute(SamlConstants.Attributes.AuthenticationMethod, null);
        //    writer.WriteString(statement.AuthenticationMethod);
        //    writer.WriteEndAttribute();
        //    writer.WriteStartAttribute(SamlConstants.Attributes.AuthenticationInstant, null);
        //    writer.WriteString(statement.AuthenticationInstant.ToString(SamlConstants.GeneratedDateTimeFormat, CultureInfo.InvariantCulture));
        //    writer.WriteEndAttribute();

        //    WriteSubject(writer, statement.Subject);

        //    if ((!string.IsNullOrEmpty(statement.IPAddress)) || (!string.IsNullOrEmpty(statement.DnsAddress)))
        //    {
        //        writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.SubjectLocality, SamlConstants.Namespace);

        //        if (!string.IsNullOrEmpty(statement.IPAddress))
        //        {
        //            writer.WriteStartAttribute(SamlConstants.Attributes.SubjectLocalityIPAddress, null);
        //            writer.WriteString(statement.IPAddress);
        //            writer.WriteEndAttribute();
        //        }

        //        if (!string.IsNullOrEmpty(statement.DnsAddress))
        //        {
        //            writer.WriteStartAttribute(SamlConstants.Attributes.SubjectLocalityDNSAddress, null);
        //            writer.WriteString(statement.DnsAddress);
        //            writer.WriteEndAttribute();
        //        }

        //        writer.WriteEndElement();
        //    }

        //    foreach (var binding in statement.AuthorityBindings)
        //    {
        //        WriteAuthorityBinding(writer, binding);
        //    }

        //    writer.WriteEndElement();
        //}

        //protected virtual void WriteAuthorityBinding(XmlWriter writer, SamlAuthorityBinding authorityBinding)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (authorityBinding == null)
        //        throw LogHelper.LogArgumentNullException(nameof(authorityBinding));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.AuthorityBinding, SamlConstants.Namespace);

        //    string prefix = null;
        //    if (!string.IsNullOrEmpty(authorityBinding.AuthorityKind.Namespace))
        //    {
        //        writer.WriteAttributeString(string.Empty, SamlConstants.NamespaceAttributePrefix, null, authorityBinding.AuthorityKind.Namespace);
        //        prefix = writer.LookupPrefix(authorityBinding.AuthorityKind.Namespace);
        //    }

        //    writer.WriteStartAttribute(SamlConstants.Attributes.AuthorityKind, null);
        //    if (string.IsNullOrEmpty(prefix))
        //        writer.WriteString(authorityBinding.AuthorityKind.Name);
        //    else
        //        writer.WriteString(prefix + ":" + authorityBinding.AuthorityKind.Name);
        //    writer.WriteEndAttribute();

        //    writer.WriteStartAttribute(SamlConstants.Attributes.Location, null);
        //    writer.WriteString(authorityBinding.Location);
        //    writer.WriteEndAttribute();

        //    writer.WriteStartAttribute(SamlConstants.Attributes.Binding, null);
        //    writer.WriteString(authorityBinding.Binding);
        //    writer.WriteEndAttribute();

        //    writer.WriteEndElement();
        //}

        //protected virtual void WriteAuthorizationDecisionStatement(XmlWriter writer, SamlAuthorizationDecisionStatement statement)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (statement == null)
        //        throw LogHelper.LogArgumentNullException(nameof(statement));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.AuthorizationDecisionStatement, SamlConstants.Namespace);

        //    writer.WriteStartAttribute(SamlConstants.Attributes.Decision, null);
        //    writer.WriteString(statement.AccessDecision.ToString());
        //    writer.WriteEndAttribute();

        //    writer.WriteStartAttribute(SamlConstants.Attributes.Resource, null);
        //    writer.WriteString(statement.Resource);
        //    writer.WriteEndAttribute();

        //    WriteSubject(writer, statement.Subject);

        //    foreach (var action in statement.Actions)
        //        WriteAction(writer, action);

        //    if (statement.Evidence != null)
        //        WriteEvidence(writer, statement.Evidence);

        //    writer.WriteEndElement();
        //}

        //protected virtual void WriteCondition(XmlWriter writer, SamlCondition condition)
        //{
        //    var audienceRestrictionCondition = condition as SamlAudienceRestrictionCondition;
        //    if (audienceRestrictionCondition != null)
        //        WriteAudienceRestrictionCondition(writer, audienceRestrictionCondition);

        //    var donotCacheCondition = condition as SamlDoNotCacheCondition;
        //    if (donotCacheCondition != null)
        //        WriteDoNotCacheCondition(writer, donotCacheCondition);
        //}

        //protected virtual void WriteConditions(XmlWriter writer, SamlConditions conditions)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (conditions == null)
        //        throw LogHelper.LogArgumentNullException(nameof(conditions));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.Conditions, SamlConstants.Namespace);
        //    if (conditions.NotBefore != DateTimeUtil.GetMinValue(DateTimeKind.Utc))
        //    {
        //        writer.WriteStartAttribute(SamlConstants.Attributes.NotBefore, null);
        //        writer.WriteString(conditions.NotBefore.ToString(SamlConstants.GeneratedDateTimeFormat, DateTimeFormatInfo.InvariantInfo));
        //        writer.WriteEndAttribute();
        //    }

        //    if (conditions.NotOnOrAfter != DateTimeUtil.GetMaxValue(DateTimeKind.Utc))
        //    {
        //        writer.WriteStartAttribute(SamlConstants.Attributes.NotOnOrAfter, null);
        //        writer.WriteString(conditions.NotOnOrAfter.ToString(SamlConstants.GeneratedDateTimeFormat, DateTimeFormatInfo.InvariantInfo));
        //        writer.WriteEndAttribute();
        //    }

        //    foreach (var condition in conditions.Conditions)
        //        WriteCondition(writer, condition);

        //    writer.WriteEndElement();
        //}

        //// TODO - figure this out when signing and maintaing node list

        /////// <summary>
        /////// Writes the source data, if available.
        /////// </summary>
        /////// <exception cref="InvalidOperationException">When no source data is available</exception>
        /////// <param name="writer"></param>
        ////public virtual void WriteSourceData(XmlWriter writer)
        ////{
        ////    if (!this.CanWriteSourceData)
        ////    {
        ////        throw LogHelper.LogExceptionMessage(new InvalidOperationException("SR.ID4140"));
        ////    }

        ////    // This call will properly just reuse the existing writer if it already qualifies
        ////    XmlDictionaryWriter dictionaryWriter = XmlDictionaryWriter.CreateDictionaryWriter(writer);
        ////    this.sourceData.SetElementExclusion(null, null);
        ////    this.sourceData.GetWriter().WriteTo(dictionaryWriter, null);
        ////}

        ////internal void WriteTo(XmlWriter writer, SamlSerializer samlSerializer)
        ////{
        ////    if (writer == null)
        ////        throw LogHelper.LogArgumentNullException(nameof(writer));

        ////    XmlDictionaryWriter dictionaryWriter = XmlDictionaryWriter.CreateDictionaryWriter(writer);

        ////    if (this.signingCredentials != null)
        ////    {
        ////        using (HashAlgorithm hash = CryptoProviderFactory.Default.CreateHashAlgorithm(this.signingCredentials.Algorithm))
        ////        {
        ////            this.hashStream = new HashStream(hash);
        ////            this.dictionaryManager = samlSerializer.DictionaryManager;
        ////            SamlDelegatingWriter delegatingWriter = new SamlDelegatingWriter(dictionaryWriter, this.hashStream, this, samlSerializer.DictionaryManager.ParentDictionary);
        ////            this.WriteXml(delegatingWriter, samlSerializer);
        ////        }
        ////    }
        ////    else
        ////    {
        ////        this.tokenStream.SetElementExclusion(null, null);
        ////        this.tokenStream.WriteTo(dictionaryWriter, samlSerializer.DictionaryManager);
        ////    }
        ////}

        //protected virtual void WriteDoNotCacheCondition(XmlWriter writer, SamlDoNotCacheCondition condition)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.DoNotCacheCondition, SamlConstants.Namespace);
        //    writer.WriteEndElement();
        //}

        //protected virtual void WriteEvidence(XmlWriter writer, SamlEvidence evidence)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (evidence == null)
        //        throw LogHelper.LogArgumentNullException(nameof(evidence));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.Evidence, SamlConstants.Namespace);

        //    foreach (var assertionId in evidence.AssertionIdReferences)
        //    {
        //        writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.AssertionIdReference, SamlConstants.Namespace);
        //        writer.WriteString(assertionId);
        //        writer.WriteEndElement();
        //    }

        //    foreach (var assertion in evidence.Assertions)
        //        WriteAssertion(writer, assertion);

        //    writer.WriteEndElement();
        //}

        //protected virtual void WriteStatement(XmlWriter writer, SamlStatement statement)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (statement == null)
        //        throw LogHelper.LogArgumentNullException(nameof(statement));

        //    var attributeStatement = statement as SamlAttributeStatement;
        //    if (attributeStatement != null)
        //    {
        //        WriteAttributeStatement(writer, attributeStatement);
        //        return;
        //    }

        //    var authenticationStatement = statement as SamlAuthenticationStatement;
        //    if (authenticationStatement != null)
        //    {
        //        WriteAuthenticationStatement(writer, authenticationStatement);
        //        return;
        //    }

        //    var authorizationStatement = statement as SamlAuthorizationDecisionStatement;
        //    if (authorizationStatement != null)
        //    {
        //        WriteAuthorizationDecisionStatement(writer, authorizationStatement);
        //        return;
        //    }

        //    throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException($"unknown statement type: {statement.GetType()}."));
        //}

        //protected virtual void WriteSubject(XmlWriter writer, SamlSubject subject)
        //{

        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (subject == null)
        //        throw LogHelper.LogArgumentNullException(nameof(subject));

        //    if (string.IsNullOrEmpty(subject.Name) && subject.ConfirmationMethods.Count == 0)
        //        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("both name and confirmation methods can not be null"));

        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.Subject, SamlConstants.Namespace);

        //    if (!string.IsNullOrEmpty(subject.Name))
        //    {
        //        writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.NameIdentifier, SamlConstants.Namespace);
        //        if (!string.IsNullOrEmpty(subject.NameFormat))
        //        {
        //            writer.WriteStartAttribute(SamlConstants.Attributes.NameIdentifierFormat, null);
        //            writer.WriteString(subject.NameFormat);
        //            writer.WriteEndAttribute();
        //        }

        //        if (!string.IsNullOrEmpty(subject.NameQualifier))
        //        {
        //            writer.WriteStartAttribute(SamlConstants.Attributes.NameIdentifierNameQualifier, null);
        //            writer.WriteString(subject.NameQualifier);
        //            writer.WriteEndAttribute();
        //        }

        //        writer.WriteString(subject.Name);
        //        writer.WriteEndElement();
        //    }

        //    if (subject.ConfirmationMethods.Count > 0)
        //    {
        //        writer.WriteStartElement(SamlConstants.PreferredPrefix, SamlConstants.Elements.SubjectConfirmation, SamlConstants.Namespace);
        //        foreach (string method in subject.ConfirmationMethods)
        //            writer.WriteElementString(SamlConstants.Elements.SubjectConfirmationMethod, SamlConstants.Namespace, method);

        //        if (!string.IsNullOrEmpty(subject.ConfirmationData))
        //            writer.WriteElementString(SamlConstants.Elements.SubjectConfirmationData, SamlConstants.Namespace, subject.ConfirmationData);

        //        if (subject.KeyIdentifier != null)
        //        {
        //            XmlDictionaryWriter dictionaryWriter = XmlDictionaryWriter.CreateDictionaryWriter(writer);
        //            // TODO - write keyinfo
        //            //SamlSerializer.WriteSecurityKeyIdentifier(dictionaryWriter, this.securityKeyIdentifier, keyInfoSerializer);
        //        }
        //        writer.WriteEndElement();
        //    }

        //    writer.WriteEndElement();
        //}

        //public virtual void WriteToken(XmlDictionaryWriter writer, SamlSecurityToken token)
        //{
        //    if (writer == null)
        //        throw LogHelper.LogArgumentNullException(nameof(writer));

        //    if (token == null)
        //        throw LogHelper.LogArgumentNullException(nameof(token));

        //    WriteAssertion(writer, token.Assertion);
        //}

        //// Helper metods to read and write SecurityKeyIdentifiers.
        //internal static SecurityKey ReadSecurityKey(XmlDictionaryReader reader)
        //{
        //    throw LogHelper.LogExceptionMessage(new InvalidOperationException("SamlSerializerUnableToReadSecurityKeyIdentifier"));
        //}

        //internal static bool IsAssertionIdValid(string assertionId)
        //{
        //    if (string.IsNullOrEmpty(assertionId))
        //        return false;

        //    // The first character of the Assertion ID should be a letter or a '_'
        //    return (((assertionId[0] >= 'A') && (assertionId[0] <= 'Z')) ||
        //        ((assertionId[0] >= 'a') && (assertionId[0] <= 'z')) ||
        //        (assertionId[0] == '_'));
        //}

        //internal static void WriteStartElementWithPreferredcPrefix(XmlWriter writer, string name, string ns)
        //{
        //    writer.WriteStartElement(SamlConstants.PreferredPrefix, name, ns);            
        //}

#pragma warning restore 1591
    }
}
