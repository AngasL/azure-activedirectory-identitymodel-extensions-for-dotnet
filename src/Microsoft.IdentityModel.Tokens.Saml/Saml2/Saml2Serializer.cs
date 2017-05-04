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
using System.Security.Claims;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// Reads and writes Saml2 Assertions and tokens
    /// </summary>
    public class Saml2Serializer
    {
        /// <summary>
        /// Instaniates a new instance of <see cref="Saml2Serializer"/>.
        /// </summary>
        public Saml2Serializer() { }

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

        /// <summary>
        /// Reads the &lt;saml:Action> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlDictionaryReader"/> positioned at a <see cref="Saml2Action"/> element.</param>
        /// <returns>A <see cref="Saml2Action"/> instance.</returns>
        protected virtual Saml2Action ReadAction(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Saml2Constants.Elements.Action, Saml2Constants.Namespace);
            try
            {
                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.ActionType, Saml2Constants.Namespace);

                // @Namespace - required
                // @attributes
                string namespaceValue = reader.GetAttribute(Saml2Constants.Attributes.Namespace);
                if (string.IsNullOrEmpty(namespaceValue))
                    throw LogReadException(LogMessages.IDX11106, Saml2Constants.Elements.Action, Saml2Constants.Attributes.Namespace);

                // TODO - relax URI.Absolute?
                if (!CanCreateValidUri(namespaceValue, UriKind.Absolute))
                    throw LogReadException(LogMessages.IDX11107, Saml2Constants.Elements.Action, Saml2Constants.Attributes.Namespace, namespaceValue);

                var action = reader.ReadElementContentAsString();
                reader.MoveToContent();
                return new Saml2Action(action, new Uri(namespaceValue));
            }
            catch (Exception ex)
            {
                if (ex is Saml2SecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.Action, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:Advice> element.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The Advice element has an extensibility point to allow XML elements
        /// from non-SAML2 namespaces to be included. By default, because the 
        /// Advice may be ignored without affecting the semantics of the 
        /// assertion, any such elements are ignored. To handle the processing
        /// of those elements, override this method.
        /// </para>
        /// </remarks>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2Advice"/> element.</param>
        /// <returns>A <see cref="Saml2Advice"/> instance.</returns>
        protected virtual Saml2Advice ReadAdvice(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Saml2Constants.Elements.Advice, Saml2Constants.Namespace);
            try
            {
                Saml2Advice advice = new Saml2Advice();
                bool isEmpty = reader.IsEmptyElement;

                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.AdviceType, Saml2Constants.Namespace);

                reader.Read();
                if (!isEmpty)
                {
                    // <AssertionIDRef|AssertionURIRef|Assertion|EncryptedAssertion|other:any> 0-OO
                    while (reader.IsStartElement())
                    {
                        // <AssertionIDRef>, <AssertionURIRef>, <Assertion>, <EncryptedAssertion>
                        if (reader.IsStartElement(Saml2Constants.Elements.AssertionIDRef, Saml2Constants.Namespace))
                            advice.AssertionIdReferences.Add(ReadSimpleNCNameElement(reader, Saml2Constants.Elements.AssertionIDRef));
                        else if (reader.IsStartElement(Saml2Constants.Elements.AssertionURIRef, Saml2Constants.Namespace))
                            advice.AssertionUriReferences.Add(ReadSimpleUriElement(reader, Saml2Constants.Elements.Advice, UriKind.RelativeOrAbsolute, false));
                        else if (reader.IsStartElement(Saml2Constants.Elements.Assertion, Saml2Constants.Namespace))
                            advice.Assertions.Add(ReadAssertion(reader));
                        else if (reader.IsStartElement(Saml2Constants.Elements.EncryptedAssertion, Saml2Constants.Namespace))
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
                if (ex is Saml2SecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.Advice, ex);
            }
        }

        /// <summary>
        /// Reads a &lt;saml:Assertion> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2Assertion"/> element.</param>
        /// <returns>A <see cref="Saml2Assertion"/> instance.</returns>
        public virtual Saml2Assertion ReadAssertion(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Saml2Constants.Elements.Assertion, Saml2Constants.Namespace);

            var envelopeReader = new EnvelopedSignatureReader(XmlDictionaryReader.CreateDictionaryReader(reader));
            var assertion = new Saml2Assertion(new Saml2NameIdentifier("__TemporaryIssuer__"));

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
                XmlUtil.ValidateXsiType(envelopeReader, Saml2Constants.Types.AssertionType, Saml2Constants.Namespace);

                // @Version - required - must be "2.0"
                string version = envelopeReader.GetAttribute(Saml2Constants.Attributes.Version);
                if (string.IsNullOrEmpty(version))
                    throw LogReadException(LogMessages.IDX11106, Saml2Constants.Elements.Assertion, Saml2Constants.Attributes.Version);

                if (!StringComparer.Ordinal.Equals(Saml2Constants.Version, version))
                    throw LogReadException(LogMessages.IDX11137, version);

                // @ID - required
                string value = envelopeReader.GetAttribute(Saml2Constants.Attributes.ID);
                if (string.IsNullOrEmpty(value))
                    throw LogReadException(LogMessages.IDX11106, Saml2Constants.Elements.Assertion, Saml2Constants.Attributes.ID);

                assertion.Id = new Saml2Id(value);

                // @IssueInstant - required
                value = envelopeReader.GetAttribute(Saml2Constants.Attributes.IssueInstant);
                if (string.IsNullOrEmpty(value))
                    throw LogReadException(LogMessages.IDX11106, Saml2Constants.Elements.Assertion, Saml2Constants.Attributes.IssueInstant);

                assertion.IssueInstant = XmlConvert.ToDateTime(value, XmlDateTimeSerializationMode.Utc);

                // will move to next element
                // <ds:Signature> 0-1 read by EnvelopedSignatureReader
                envelopeReader.Read();
               
                // <Issuer> 1
                assertion.Issuer = ReadIssuer(envelopeReader);

                // <Subject> 0-1
                if (envelopeReader.IsStartElement(Saml2Constants.Elements.Subject, Saml2Constants.Namespace))
                    assertion.Subject = ReadSubject(envelopeReader);

                // <Conditions> 0-1
                if (envelopeReader.IsStartElement(Saml2Constants.Elements.Conditions, Saml2Constants.Namespace))
                    assertion.Conditions = ReadConditions(envelopeReader);

                // <Advice> 0-1
                if (envelopeReader.IsStartElement(Saml2Constants.Elements.Advice, Saml2Constants.Namespace))
                    assertion.Advice = ReadAdvice(envelopeReader);

                // <Statement|AuthnStatement|AuthzDecisionStatement|AttributeStatement>, 0-OO
                while (envelopeReader.IsStartElement())
                {
                    Saml2Statement statement;

                    if (envelopeReader.IsStartElement(Saml2Constants.Elements.Statement, Saml2Constants.Namespace))
                        statement = ReadStatement(envelopeReader);
                    else if (envelopeReader.IsStartElement(Saml2Constants.Elements.AttributeStatement, Saml2Constants.Namespace))
                        statement = ReadAttributeStatement(envelopeReader);
                    else if (envelopeReader.IsStartElement(Saml2Constants.Elements.AuthnStatement, Saml2Constants.Namespace))
                        statement = ReadAuthenticationStatement(envelopeReader);
                    else if (envelopeReader.IsStartElement(Saml2Constants.Elements.AuthzDecisionStatement, Saml2Constants.Namespace))
                        statement = ReadAuthorizationDecisionStatement(envelopeReader);
                    else
                        break;

                    assertion.Statements.Add(statement);
                }

                envelopeReader.ReadEndElement();
                if (null == assertion.Subject)
                {
                    // An assertion with no statements MUST contain a <Subject> element. [Saml2Core, line 585]
                    if (0 == assertion.Statements.Count)
                        throw LogReadException(LogMessages.IDX11108, Saml2Constants.Elements.Assertion);

                    // Furthermore, the built-in statement types all require the presence of a subject.
                    // [Saml2Core, lines 1050, 1168, 1280]
                    foreach (Saml2Statement statement in assertion.Statements)
                    {
                        if (statement is Saml2AuthenticationStatement
                            || statement is Saml2AttributeStatement
                            || statement is Saml2AuthorizationDecisionStatement)
                        {
                            throw LogReadException(LogMessages.IDX11109, Saml2Constants.Elements.Assertion);
                        }
                    }
                }

                // attach signedXml for validation of signature
                assertion.Signature = envelopeReader.Signature;
                return assertion;
            }
            catch (Exception ex)
            {
                if (ex is Saml2SecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.Assertion, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:Attribute> element.
        /// </summary>
        /// <remarks>
        /// The default implementation requires that the content of the
        /// Attribute element be a simple string. To handle complex content
        /// or content of declared simple types other than xs:string, override
        /// this method.
        /// </remarks>
        /// <param name="reader">An <see cref="XmlReader"/> positioned at a <see cref="Saml2Attribute"/> element.</param>
        /// <returns>A <see cref="Saml2Attribute"/> instance.</returns>
        public virtual Saml2Attribute ReadAttribute(XmlDictionaryReader reader)
        {
            // TODO this is public temporaroly until 'actor' processing
            XmlUtil.CheckReaderOnEntry(reader, Saml2Constants.Elements.Attribute, Saml2Constants.Namespace);
            try
            {
                Saml2Attribute attribute;
                bool isEmpty = reader.IsEmptyElement;

                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.AttributeType, Saml2Constants.Namespace);

                // @Name - required
                string value = reader.GetAttribute(Saml2Constants.Attributes.Name);
                if (string.IsNullOrEmpty(value))
                    throw LogReadException(LogMessages.IDX11106, Saml2Constants.Elements.Attribute, Saml2Constants.Attributes.Name);

                attribute = new Saml2Attribute(value);

                // @NameFormat - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.NameFormat);
                if (!string.IsNullOrEmpty(value))
                {
                    if (!CanCreateValidUri(value, UriKind.Absolute))
                        LogReadException(LogMessages.IDX11107, Saml2Constants.Elements.Attribute, Saml2Constants.Attributes.NameFormat, value);

                    attribute.NameFormat = new Uri(value);
                }

                // @FriendlyName - optional
                attribute.FriendlyName = reader.GetAttribute(Saml2Constants.Attributes.FriendlyName);

                // @OriginalIssuer - optional
                attribute.OriginalIssuer = reader.GetAttribute(Saml2Constants.Attributes.OriginalIssuer);

                // content
                reader.Read();
                if (!isEmpty)
                {
                    while (reader.IsStartElement(Saml2Constants.Elements.AttributeValue, Saml2Constants.Namespace))
                    {
                        bool isEmptyValue = reader.IsEmptyElement;
                        bool isNil = XmlUtil.IsNil(reader);

                        // Lax on receive. If we dont find the AttributeValueXsiType in the format we are looking for in the xml, we default to string.
                        // Read the xsi:type. We are expecting a value of the form "some-non-empty-string" or "some-non-empty-local-prefix:some-non-empty-string".
                        // ":some-non-empty-string" and "some-non-empty-string:" are edge-cases where defaulting to string is reasonable.
                        // For attributeValueXsiTypeSuffix, we want the portion after the local prefix in "some-non-empty-local-prefix:some-non-empty-string"
                        // "some-non-empty-local-prefix:some-non-empty-string" case
                        string attributeValueXsiTypePrefix = null;
                        string attributeValueXsiTypeSuffix = null;
                        string attributeValueXsiTypeSuffixWithLocalPrefix = reader.GetAttribute(Saml2Constants.Attributes.Type, XmlSignatureConstants.XmlSchemaNamespace);
                        if (!string.IsNullOrEmpty(attributeValueXsiTypeSuffixWithLocalPrefix))
                        {
                            // "some-non-empty-string" case
                            if (attributeValueXsiTypeSuffixWithLocalPrefix.IndexOf(":", StringComparison.Ordinal) == -1)
                            {
                                attributeValueXsiTypePrefix = reader.LookupNamespace(string.Empty);
                                attributeValueXsiTypeSuffix = attributeValueXsiTypeSuffixWithLocalPrefix;
                            }
                            else if (attributeValueXsiTypeSuffixWithLocalPrefix.IndexOf(":", StringComparison.Ordinal) > 0 &&
                                      attributeValueXsiTypeSuffixWithLocalPrefix.IndexOf(":", StringComparison.Ordinal) < attributeValueXsiTypeSuffixWithLocalPrefix.Length - 1)
                            {
                                string localPrefix = attributeValueXsiTypeSuffixWithLocalPrefix.Substring(0, attributeValueXsiTypeSuffixWithLocalPrefix.IndexOf(":", StringComparison.Ordinal));
                                attributeValueXsiTypePrefix = reader.LookupNamespace(localPrefix);
                                attributeValueXsiTypeSuffix = attributeValueXsiTypeSuffixWithLocalPrefix.Substring(attributeValueXsiTypeSuffixWithLocalPrefix.IndexOf(":", StringComparison.Ordinal) + 1);
                            }
                        }

                        if (attributeValueXsiTypePrefix != null && attributeValueXsiTypeSuffix != null)
                            attribute.AttributeValueXsiType = String.Concat(attributeValueXsiTypePrefix, "#", attributeValueXsiTypeSuffix);

                        if (isNil)
                        {
                            reader.Read();
                            if (!isEmptyValue)
                            {
                                reader.ReadEndElement();
                            }

                            attribute.Values.Add(null);
                        }
                        else if (isEmptyValue)
                        {
                            reader.Read();
                            attribute.Values.Add(string.Empty);
                        }
                        else
                        {
                            attribute.Values.Add(ReadAttributeValue(reader, attribute));
                        }
                    }

                    reader.ReadEndElement();
                }

                return attribute;
            }
            catch (Exception ex)
            {
                if (ex is Saml2SecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.Attribute, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:AttributeStatement> element, or a
        /// &lt;saml:Statement element that specifies an xsi:type of
        /// saml:AttributeStatementType.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2AttributeStatement"/> element.</param>
        /// <returns>A <see cref="Saml2AttributeStatement"/> instance.</returns>
        protected virtual Saml2AttributeStatement ReadAttributeStatement(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Saml2Constants.Elements.AttributeStatement, Saml2Constants.Namespace);
            try
            {
                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.AttributeStatementType, Saml2Constants.Namespace);

                // Content
                var statement = new Saml2AttributeStatement();
                reader.Read();

                // <Attribute|EncryptedAttribute> 1-OO
                while (reader.IsStartElement())
                {
                    if (reader.IsStartElement(Saml2Constants.Elements.EncryptedAttribute, Saml2Constants.Namespace))
                        throw LogReadException(LogMessages.IDX11117);
                    else if (reader.IsStartElement(Saml2Constants.Elements.Attribute, Saml2Constants.Namespace))
                        statement.Attributes.Add(ReadAttribute(reader));
                    else
                        break;
                }

                // At least one attribute expected
                if (statement.Attributes.Count == 0)
                    throw LogReadException(LogMessages.IDX11138);

                reader.ReadEndElement();
                return statement;
            }
            catch (Exception ex)
            {
                if (ex is Saml2SecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.AttributeStatement, ex);
            }
        }

        /// <summary>
        /// Reads an attribute value.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2Attribute"/>.</param>
        /// <param name="attribute">The <see cref="Saml2Attribute"/>.</param>
        /// <returns>The attribute value as a string.</returns>
        /// <exception cref="ArgumentNullException">The input parameter 'reader' is null.</exception>
        protected virtual string ReadAttributeValue(XmlDictionaryReader reader, Saml2Attribute attribute)
        {
            // This code was designed realizing that the writter of the xml controls how our
            // reader will report the NodeType. A completely differnet system (IBM, etc) could write the values.
            // Considering NodeType is important, because we need to read the entire value, end element and not loose anything significant.
            //
            // Couple of cases to help understand the design choices.
            //
            // 1.
            // "<MyElement xmlns="urn:mynamespace"><another>complex</another></MyElement><sibling>value</sibling>"
            // Could result in the our reader reporting the NodeType as Text OR Element, depending if '<' was entitized to '&lt;'
            //
            // 2.
            // " <MyElement xmlns="urn:mynamespace"><another>complex</another></MyElement><sibling>value</sibling>"
            // Could result in the our reader reporting the NodeType as Text OR Whitespace.  Post Whitespace processing, the NodeType could be
            // reported as Text or Element, depending if '<' was entitized to '&lt;'
            //
            // 3.
            // "/r/n/t   "
            // Could result in the our reader reporting the NodeType as whitespace.
            //
            // Since an AttributeValue with ONLY Whitespace and a complex Element proceeded by whitespace are reported as the same NodeType (2. and 3.)
            // the whitespace is remembered and discarded if an element is found, otherwise it becomes the value. This is to help users who accidently put a space when adding claims
            // If we just skipped the Whitespace, then an AttributeValue that started with Whitespace would loose that part and claims generated from the AttributeValue
            // would be missing that part.
            //

            XmlUtil.CheckReaderOnEntry(reader, Saml2Constants.Elements.AttributeValue, Saml2Constants.Namespace);

            string result = string.Empty;
            string whiteSpace = string.Empty;

            try
            {
                while (reader.NodeType == XmlNodeType.Whitespace)
                {
                    whiteSpace += reader.Value;
                    reader.Read();
                }

                reader.ReadStartElement(Saml2Constants.Elements.AttributeValue, Saml2Constants.Namespace);
                if (reader.NodeType == XmlNodeType.Element)
                {
                    while (reader.NodeType == XmlNodeType.Element)
                    {
                        result += reader.ReadOuterXml();
                        reader.MoveToContent();
                    }
                }
                else
                {
                    result = whiteSpace;
                    result += reader.ReadContentAsString();
                }

                reader.ReadEndElement();
                return result;
            }
            catch (Exception ex)
            {
                if (ex is Saml2SecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.AttributeValue, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:AudienceRestriction> element or a 
        /// &lt;saml:Condition> element that specifies an xsi:type
        /// of saml:AudienceRestrictionType.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2AudienceRestriction"/> element.</param>
        /// <returns>A <see cref="Saml2AudienceRestriction"/> instance.</returns>
        protected virtual Saml2AudienceRestriction ReadAudienceRestriction(XmlDictionaryReader reader)
        {
            if (null == reader)
                LogHelper.LogArgumentNullException(nameof(reader));

            // throw if wrong element
            bool isConditionElement = false;
            if (reader.IsStartElement(Saml2Constants.Elements.Condition, Saml2Constants.Namespace))
                isConditionElement = true;
            else if (!reader.IsStartElement(Saml2Constants.Elements.AudienceRestriction, Saml2Constants.Namespace))
                throw LogReadException(LogMessages.IDX11105, Saml2Constants.Elements.AudienceRestriction, reader.Name);

            try
            {
                // disallow empty
                if (reader.IsEmptyElement)
                    LogReadException(LogMessages.IDX11104, Saml2Constants.Elements.AudienceRestriction);

                Saml2AudienceRestriction audienceRestriction;

                // @xsi:type -- if we're a <Condition> element, this declaration must be present
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.AudienceRestrictionType, Saml2Constants.Namespace, isConditionElement);


                // content
                reader.Read();

                // <Audience> - 1-OO
                if (!reader.IsStartElement(Saml2Constants.Elements.Audience, Saml2Constants.Namespace))
                    throw LogReadException(LogMessages.IDX11105, Saml2Constants.Elements.Audience, reader.Name);

                // We are now laxing the uri check for audience restriction to support interop partners 
                // This is a specific request from server : Bug 11850
                // ReadSimpleUriElement now has a flag that turns lax reading ON/OFF.
                audienceRestriction = new Saml2AudienceRestriction(ReadSimpleUriElement(reader, Saml2Constants.Elements.Audience, UriKind.RelativeOrAbsolute, false).OriginalString);
                while (reader.IsStartElement(Saml2Constants.Elements.Audience, Saml2Constants.Namespace))
                {
                    audienceRestriction.Audiences.Add(ReadSimpleUriElement(reader, Saml2Constants.Elements.Audience, UriKind.RelativeOrAbsolute, false).OriginalString);
                }

                reader.ReadEndElement();
                return audienceRestriction;
            }
            catch (Exception ex)
            {
                if (ex is Saml2SecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.Audience, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:AuthnContext> element.
        /// </summary>
        /// <remarks>
        /// The default implementation does not handle the optional
        /// &lt;saml:AuthnContextDecl> element. To handle by-value
        /// authentication context declarations, override this method.
        /// </remarks>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2AuthenticationContext"/> element.</param>
        /// <returns>A <see cref="Saml2AuthenticationContext"/> instance.</returns>
        protected virtual Saml2AuthenticationContext ReadAuthenticationContext(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Saml2Constants.Elements.AuthnContext, Saml2Constants.Namespace);
            try
            {
                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.AuthnContextType, Saml2Constants.Namespace);

                // Content
                reader.ReadStartElement();

                // At least one of ClassRef and ( Decl XOR DeclRef) must be present
                // At this time, we do not support Decl, which is a by-value 
                // authentication context declaration.
                Uri classRef = null;
                Uri declRef = null;

                // <AuthnContextClassRef> - see comment above
                if (reader.IsStartElement(Saml2Constants.Elements.AuthnContextClassRef, Saml2Constants.Namespace))
                    classRef = ReadSimpleUriElement(reader, Saml2Constants.Elements.AuthnContextClassRef, UriKind.RelativeOrAbsolute, false);

                // <AuthnContextDecl> - see comment above
                if (reader.IsStartElement(Saml2Constants.Elements.AuthnContextDecl, Saml2Constants.Namespace))
                    throw LogReadException(LogMessages.IDX11118);

                // <AuthnContextDeclRef> - see comment above
                // If there was no ClassRef, there must be a DeclRef
                if (reader.IsStartElement(Saml2Constants.Elements.AuthnContextDeclRef, Saml2Constants.Namespace))
                    declRef = ReadSimpleUriElement(reader, Saml2Constants.Elements.AuthnContextDeclRef, UriKind.RelativeOrAbsolute, false);
                else if (null == classRef)
                    reader.ReadStartElement(Saml2Constants.Elements.AuthnContextDeclRef, Saml2Constants.Namespace);

                // Now we have enough data to create the object
                // TODO - relax URI - string?
                var authnContext = new Saml2AuthenticationContext(classRef, declRef);

                // <AuthenticatingAuthority> - 0-OO
                while (reader.IsStartElement(Saml2Constants.Elements.AuthenticatingAuthority, Saml2Constants.Namespace))
                    authnContext.AuthenticatingAuthorities.Add(ReadSimpleUriElement(reader, Saml2Constants.Elements.AuthenticatingAuthority, UriKind.RelativeOrAbsolute, false));

                reader.ReadEndElement();
                return authnContext;
            }
            catch (Exception ex)
            {
                if (ex is Saml2SecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.AuthnContext, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:AuthnStatement> element or a &lt;saml:Statement>
        /// element that specifies an xsi:type of saml:AuthnStatementType.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2AuthenticationStatement"/> element.</param>
        /// <returns>A <see cref="Saml2AuthenticationStatement"/> instance.</returns>
        protected virtual Saml2AuthenticationStatement ReadAuthenticationStatement(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Saml2Constants.Elements.AuthnStatement, Saml2Constants.Namespace);
            try
            {
                // Must cache the individual data since the required
                // AuthnContext comes last
                DateTime authnInstant;
                Saml2AuthenticationContext authnContext;
                string sessionIndex;
                DateTime? sessionNotOnOrAfter = null;
                Saml2SubjectLocality subjectLocality = null;

                // defer disallowing empty until after xsi:type
                bool isEmpty = reader.IsEmptyElement;

                // @attributes
                string value;

                // @xsi:type -- if we're a <Statement> element, this declaration must be present
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.AuthnStatementType, Saml2Constants.Namespace, false);

                // @AuthnInstant - required
                value = reader.GetAttribute(Saml2Constants.Attributes.AuthnInstant);
                if (string.IsNullOrEmpty(value))
                    throw LogReadException(LogMessages.IDX11106, Saml2Constants.Elements.AuthnStatement, Saml2Constants.Attributes.AuthnInstant);

                // TODO - net1.4 doesn't support array of formats.
                // authnInstant = XmlConvert.ToDateTime(value, Saml2Constants.AcceptedDateTimeFormats);
                authnInstant = XmlConvert.ToDateTime(value, XmlDateTimeSerializationMode.Utc);

                // @SessionIndex - optional
                sessionIndex = reader.GetAttribute(Saml2Constants.Attributes.SessionIndex);

                // @SessionNotOnOrAfter - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.SessionNotOnOrAfter);
                if (!string.IsNullOrEmpty(value))
                    sessionNotOnOrAfter = XmlConvert.ToDateTime(value, XmlDateTimeSerializationMode.Utc);

                // Content
                reader.Read();

                // <SubjectLocality> 0-1
                if (reader.IsStartElement(Saml2Constants.Elements.SubjectLocality, Saml2Constants.Namespace))
                    subjectLocality = ReadSubjectLocality(reader);

                // <AuthnContext> 1
                authnContext = ReadAuthenticationContext(reader);

                reader.ReadEndElement();

                // Construct the actual object
                var authnStatement = new Saml2AuthenticationStatement(authnContext, authnInstant);
                authnStatement.SessionIndex = sessionIndex;
                authnStatement.SessionNotOnOrAfter = sessionNotOnOrAfter;
                authnStatement.SubjectLocality = subjectLocality;
                return authnStatement;
            }
            catch (Exception ex)
            {
                if (ex is Saml2SecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.AuthnStatement, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:AuthzDecisionStatement> element or a
        /// &lt;saml:Statement element that specifies an xsi:type of
        /// saml:AuthzDecisionStatementType.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2AuthorizationDecisionStatement"/> element.</param>
        /// <returns>A <see cref="Saml2AuthorizationDecisionStatement"/> instance.</returns>
        protected virtual Saml2AuthorizationDecisionStatement ReadAuthorizationDecisionStatement(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Saml2Constants.Elements.AuthzDecisionStatement, Saml2Constants.Namespace);
            try
            {
                // Need the attributes before we can instantiate
                Saml2AuthorizationDecisionStatement statement;
                Uri resource;

                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.AuthzDecisionStatementType, Saml2Constants.Namespace, false);

                // @Decision - required
                var decision = reader.GetAttribute(Saml2Constants.Attributes.Decision);
                if (string.IsNullOrEmpty(decision))
                    throw LogReadException(LogMessages.IDX11106, Saml2Constants.Elements.AuthzDecisionStatement, Saml2Constants.Attributes.Decision);

                // @Resource - required

                // @attributes
                string value = reader.GetAttribute(Saml2Constants.Attributes.Resource);
                if (null == value)
                {
                    throw LogReadException(LogMessages.IDX11106, Saml2Constants.Elements.AuthzDecisionStatement, Saml2Constants.Attributes.Resource);
                }
                else if (0 == value.Length)
                {
                    resource = Saml2AuthorizationDecisionStatement.EmptyResource;
                }
                else
                {
                    if (!CanCreateValidUri(value, UriKind.Absolute))
                        throw LogReadException(LogMessages.IDX11107, Saml2Constants.Elements.AuthzDecisionStatement, Saml2Constants.Attributes.Resource, value);

                    resource = new Uri(value);
                }

                // Content
                statement = new Saml2AuthorizationDecisionStatement(resource, decision);
                reader.Read();

                // <Action> 1-OO
                do
                {
                    statement.Actions.Add(ReadAction(reader));
                }
                while (reader.IsStartElement(Saml2Constants.Elements.Action, Saml2Constants.Namespace));

                // <Evidence> 0-1
                if (reader.IsStartElement(Saml2Constants.Elements.Evidence, Saml2Constants.Namespace))
                    statement.Evidence = ReadEvidence(reader);

                reader.ReadEndElement();
                return statement;
            }
            catch (Exception ex)
            {
                if (ex is Saml2SecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.AuthnStatement, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:Conditions> element.
        /// </summary>
        /// <remarks>
        /// To handle custom &lt;saml:Condition> elements, override this
        /// method.
        /// </remarks>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2Conditions"/> element.</param>
        /// <returns>A <see cref="Saml2Conditions"/> instance.</returns>
        protected virtual Saml2Conditions ReadConditions(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Saml2Constants.Elements.Conditions, Saml2Constants.Namespace);
            try
            {
                Saml2Conditions conditions = new Saml2Conditions();
                bool isEmpty = reader.IsEmptyElement;

                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.ConditionsType, Saml2Constants.Namespace);

                // @NotBefore - optional
                var value = reader.GetAttribute(Saml2Constants.Attributes.NotBefore);
                if (!string.IsNullOrEmpty(value))
                    conditions.NotBefore = XmlConvert.ToDateTime(value, XmlDateTimeSerializationMode.Utc);

                // @NotOnOrAfter - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.NotOnOrAfter);
                if (!string.IsNullOrEmpty(value))
                    conditions.NotOnOrAfter = XmlConvert.ToDateTime(value, XmlDateTimeSerializationMode.Utc);

                // Content
                reader.ReadStartElement();
                if (!isEmpty)
                {
                    // <Condition|AudienceRestriction|OneTimeUse|ProxyRestriction>, 0-OO
                    while (reader.IsStartElement())
                    {
                        // <Condition> - 0-OO
                        if (reader.IsStartElement(Saml2Constants.Elements.Condition, Saml2Constants.Namespace))
                        {
                            // Since Condition is abstract, must process based on xsi:type
                            XmlQualifiedName declaredType = XmlUtil.GetXsiType(reader);

                            // No type, throw
                            if (null == declaredType
                                || XmlUtil.EqualsQName(declaredType, Saml2Constants.Types.ConditionAbstractType, Saml2Constants.Namespace))
                            {
                                throw LogReadException(LogMessages.IDX11119, reader.LocalName, reader.NamespaceURI);
                            }
                            else if (XmlUtil.EqualsQName(declaredType, Saml2Constants.Types.AudienceRestrictionType, Saml2Constants.Namespace))
                            {
                                conditions.AudienceRestrictions.Add(ReadAudienceRestriction(reader));
                            }
                            else if (XmlUtil.EqualsQName(declaredType, Saml2Constants.Types.OneTimeUseType, Saml2Constants.Namespace))
                            {
                                if (conditions.OneTimeUse)
                                    throw LogReadException(LogMessages.IDX11120, Saml2Constants.Elements.OneTimeUse);

                                ReadEmptyContentElement(reader);
                                conditions.OneTimeUse = true;
                            }
                            else if (XmlUtil.EqualsQName(declaredType, Saml2Constants.Types.ProxyRestrictionType, Saml2Constants.Namespace))
                            {
                                if (null != conditions.ProxyRestriction)
                                    throw LogReadException(LogMessages.IDX11120, Saml2Constants.Elements.ProxyRestricton);

                                conditions.ProxyRestriction = ReadProxyRestriction(reader);
                            }
                            else
                            {
                                // Unknown type - Instruct the user to override to handle custom <Condition>
                                throw LogReadException(LogMessages.IDX11121);
                            }
                        }
                        else if (reader.IsStartElement(Saml2Constants.Elements.AudienceRestriction, Saml2Constants.Namespace))
                        {
                            conditions.AudienceRestrictions.Add(ReadAudienceRestriction(reader));
                        }
                        else if (reader.IsStartElement(Saml2Constants.Elements.OneTimeUse, Saml2Constants.Namespace))
                        {
                            if (conditions.OneTimeUse)
                            {
                                throw LogReadException(LogMessages.IDX11120, Saml2Constants.Elements.OneTimeUse);
                            }

                            ReadEmptyContentElement(reader);
                            conditions.OneTimeUse = true;
                        }
                        else if (reader.IsStartElement(Saml2Constants.Elements.ProxyRestricton, Saml2Constants.Namespace))
                        {
                            if (null != conditions.ProxyRestriction)
                                throw LogReadException(LogMessages.IDX11120, Saml2Constants.Elements.ProxyRestricton);

                            conditions.ProxyRestriction = ReadProxyRestriction(reader);
                        }
                        else
                        {
                            break;
                        }
                    }

                    reader.ReadEndElement();
                }

                return conditions;
            }
            catch (Exception ex)
            {
                if (ex is Saml2SecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.Conditions, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:EncryptedId> element.
        /// </summary>
        /// <param name="reader"><see cref="XmlReader"/> pointing at the XML EncryptedId element</param>
        /// <returns>An instance of <see cref="Saml2NameIdentifier"/> representing the EncryptedId that was read</returns>
        /// <exception cref="ArgumentNullException">The input parameter 'reader' is null.</exception>
        /// <exception cref="NotImplementedException">Not implemented right now.</exception>
        protected virtual Saml2NameIdentifier ReadEncryptedId(XmlDictionaryReader reader)
        {
            throw new NotImplementedException("not implemented yet");
            //if (null == reader)
            //{
            //    throw LogHelper.LogArgumentNullException(nameof(reader));
            //}

            //reader.MoveToContent();

            //if (!reader.IsStartElement(Saml2Constants.Elements.EncryptedID, Saml2Constants.Namespace))
            //{
            //    // throw if wrong element
            //    reader.ReadStartElement(Saml2Constants.Elements.EncryptedID, Saml2Constants.Namespace);
            //}

            //Collection<EncryptedKeyIdentifierClause> clauses = new Collection<EncryptedKeyIdentifierClause>();
            //EncryptingCredentials encryptingCredentials = null;
            //Saml2NameIdentifier saml2NameIdentifier = null;

            //using (StringReader sr = new StringReader(reader.ReadOuterXml()))
            //{
            //    using (XmlDictionaryReader wrappedReader = new WrappedXmlDictionaryReader(XmlReader.Create(sr), XmlDictionaryReaderQuotas.Max))
            //    {
            //        XmlReader plaintextReader = CreatePlaintextReaderFromEncryptedData(
            //                    wrappedReader,
            //                    Configuration.ServiceTokenResolver,
            //                    this.KeyInfoSerializer,
            //                    clauses,
            //                    out encryptingCredentials);

            //        saml2NameIdentifier = this.ReadNameIdType(plaintextReader);
            //        saml2NameIdentifier.EncryptingCredentials = encryptingCredentials;
            //        foreach (EncryptedKeyIdentifierClause clause in clauses)
            //        {
            //            saml2NameIdentifier.ExternalEncryptedKeys.Add(clause);
            //        }
            //    }
            //}

            //return saml2NameIdentifier;
        }

        /// <summary>
        /// Reads the &lt;saml:Evidence> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2Evidence"/> element.</param>
        /// <returns>A <see cref="Saml2Evidence"/> instance.</returns>
        protected virtual Saml2Evidence ReadEvidence(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Saml2Constants.Elements.Evidence, Saml2Constants.Namespace);
            try
            {
                Saml2Evidence evidence = new Saml2Evidence();

                // @attributes

                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.EvidenceType, Saml2Constants.Namespace);

                reader.Read();

                // <AssertionIDRef|AssertionURIRef|Assertion|EncryptedAssertion> 0-OO
                while (reader.IsStartElement())
                {
                    if (reader.IsStartElement(Saml2Constants.Elements.AssertionIDRef, Saml2Constants.Namespace))
                    {
                        evidence.AssertionIdReferences.Add(ReadSimpleNCNameElement(reader, Saml2Constants.Elements.AssertionIDRef));
                    }
                    else if (reader.IsStartElement(Saml2Constants.Elements.AssertionURIRef, Saml2Constants.Namespace))
                    {
                        evidence.AssertionUriReferences.Add(ReadSimpleUriElement(reader, Saml2Constants.Elements.AssertionURIRef, UriKind.RelativeOrAbsolute, false));
                    }
                    else if (reader.IsStartElement(Saml2Constants.Elements.Assertion, Saml2Constants.Namespace))
                    {
                        evidence.Assertions.Add(ReadAssertion(reader));
                    }
                    else if (reader.IsStartElement(Saml2Constants.Elements.EncryptedAssertion, Saml2Constants.Namespace))
                    {
                        evidence.Assertions.Add(ReadAssertion(reader));
                    }
                }

                if (0 == evidence.AssertionIdReferences.Count
                 && 0 == evidence.Assertions.Count
                 && 0 == evidence.AssertionUriReferences.Count)
                    throw LogReadException(LogMessages.IDX11122);

                reader.ReadEndElement();

                return evidence;
            }
            catch (Exception ex)
            {
                if (ex is Saml2SecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.Evidence, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:Issuer> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2NameIdentifier"/> element.</param>
        /// <returns>A <see cref="Saml2NameIdentifier"/> instance.</returns>
        protected virtual Saml2NameIdentifier ReadIssuer(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Saml2Constants.Elements.Issuer, Saml2Constants.Namespace);
            return ReadNameIdType(reader);
        }

        /// <summary>
        /// Reads the &lt;saml:NameID> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2NameIdentifier"/> element.</param>
        /// <returns>An instance of <see cref="Saml2NameIdentifier"/></returns>
        /// <exception cref="ArgumentNullException">The input parameter 'reader' is null.</exception>
        protected virtual Saml2NameIdentifier ReadNameId(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Saml2Constants.Elements.NameID, Saml2Constants.Namespace);
            return ReadNameIdType(reader);
        }

        /// <summary>
        /// Both &lt;Issuer> and &lt;NameID> are of NameIDType. This method reads
        /// the content of either one of those elements.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2NameIdentifier"/> element.</param>
        /// <returns>An instance of <see cref="Saml2NameIdentifier"/></returns>
        internal Saml2NameIdentifier ReadNameIdType(XmlDictionaryReader reader)
        {
            // check that reader is on correct element is made by caller
            try
            {
                Saml2NameIdentifier nameIdentifier = new Saml2NameIdentifier("__TemporaryName__");

                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.NameIDType, Saml2Constants.Namespace);

                // @Format - optional
                string value = reader.GetAttribute(Saml2Constants.Attributes.Format);
                if (!string.IsNullOrEmpty(value))
                {
                    if (!CanCreateValidUri(value, UriKind.Absolute))
                        throw LogReadException(LogMessages.IDX11107, Saml2Constants.Types.NameIDType, Saml2Constants.Attributes.Format, value);

                    nameIdentifier.Format = new Uri(value);
                }

                // @NameQualifier - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.NameQualifier);
                if (!string.IsNullOrEmpty(value))
                    nameIdentifier.NameQualifier = value;

                // @SPNameQualifier - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.SPNameQualifier);
                if (!string.IsNullOrEmpty(value))
                    nameIdentifier.SPNameQualifier = value;

                // @SPProvidedID - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.SPProvidedID);
                if (!string.IsNullOrEmpty(value))
                    nameIdentifier.SPProvidedId = value;

                // Content is string
                nameIdentifier.Value = reader.ReadElementContentAsString();

                // According to section 8.3.6, if the name identifier format is of type 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity'
                // the name identifier value must be a uri and name qualifier, spname qualifier, and spprovided id must be omitted.
                if (nameIdentifier.Format != null &&
                    StringComparer.Ordinal.Equals(nameIdentifier.Format.OriginalString, Saml2Constants.NameIdentifierFormats.Entity.OriginalString))
                {
                    if (!CanCreateValidUri(nameIdentifier.Value, UriKind.Absolute))
                        throw LogReadException(LogMessages.IDX11107, Saml2Constants.Elements.NameID, Saml2Constants.Types.NameIDType, nameIdentifier.Value);

                    if (!string.IsNullOrEmpty(nameIdentifier.NameQualifier)
                        || !string.IsNullOrEmpty(nameIdentifier.SPNameQualifier)
                        || !string.IsNullOrEmpty(nameIdentifier.SPProvidedId))
                        throw LogReadException(LogMessages.IDX11124, nameIdentifier.Value, Saml2Constants.NameIdentifierFormats.Entity.OriginalString);
                }

                return nameIdentifier;
            }
            catch (Exception ex)
            {
                if (ex is Saml2SecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Types.NameIDType, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:ProxyRestriction> element, or a &lt;saml:Condition>
        /// element that specifies an xsi:type of saml:ProxyRestrictionType.
        /// </summary>
        /// <remarks>
        /// In the default implementation, the maximum value of the Count attribute
        /// is limited to Int32.MaxValue.
        /// </remarks>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2ProxyRestriction"/> element.</param>
        /// <returns>An instance of <see cref="Saml2ProxyRestriction"/></returns>
        protected virtual Saml2ProxyRestriction ReadProxyRestriction(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            // throw if wrong element
            bool isConditionElement = false;
            if (reader.IsStartElement(Saml2Constants.Elements.Condition, Saml2Constants.Namespace))
                isConditionElement = true;
            else if (!reader.IsStartElement(Saml2Constants.Elements.ProxyRestricton, Saml2Constants.Namespace))

                reader.ReadStartElement(Saml2Constants.Elements.ProxyRestricton, Saml2Constants.Namespace);

            try
            {
                Saml2ProxyRestriction proxyRestriction = new Saml2ProxyRestriction();
                bool isEmpty = reader.IsEmptyElement;

                // @attributes
                string value;

                // @xsi:type -- if we're a <Condition> element, this declaration must be present
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.ProxyRestrictionType, Saml2Constants.Namespace, isConditionElement);

                // @Count - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.Count);
                if (!string.IsNullOrEmpty(value))
                {
                    proxyRestriction.Count = XmlConvert.ToInt32(value);
                }

                // content
                reader.Read();
                if (!isEmpty)
                {
                    // <Audience> - 0-OO
                    while (reader.IsStartElement(Saml2Constants.Elements.Audience, Saml2Constants.Namespace))
                    {
                        proxyRestriction.Audiences.Add(ReadSimpleUriElement(reader, Saml2Constants.Elements.Audience, UriKind.RelativeOrAbsolute, false));
                    }

                    reader.ReadEndElement();
                }

                return proxyRestriction;
            }
            catch (Exception ex)
            {
                if (ex is Saml2SecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.ProxyRestricton, ex);
            }
        }

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
        protected virtual Saml2Statement ReadStatement(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Saml2Constants.Elements.Statement, Saml2Constants.Namespace);

            // Since Statement is an abstract type, we have to switch off the xsi:type declaration
            XmlQualifiedName declaredType = XmlUtil.GetXsiType(reader);

            // No declaration, or declaring that this is just a "Statement", is invalid since
            // statement is abstract
            if (null == declaredType
                || XmlUtil.EqualsQName(declaredType, Saml2Constants.Types.StatementAbstractType, Saml2Constants.Namespace))
                throw LogReadException(LogMessages.IDX11119, reader.LocalName, reader.NamespaceURI);

            // Reroute to the known statement types if applicable
            if (XmlUtil.EqualsQName(declaredType, Saml2Constants.Types.AttributeStatementType, Saml2Constants.Namespace))
                return ReadAttributeStatement(reader);
            else if (XmlUtil.EqualsQName(declaredType, Saml2Constants.Types.AuthnStatementType, Saml2Constants.Namespace))
                return ReadAuthenticationStatement(reader);
            else if (XmlUtil.EqualsQName(declaredType, Saml2Constants.Types.AuthzDecisionStatementType, Saml2Constants.Namespace))
                return ReadAuthorizationDecisionStatement(reader);
            else
                throw LogReadException(LogMessages.IDX11119, declaredType.Name, declaredType.Namespace);
        }

        /// <summary>
        /// Reads the &lt;saml:Subject> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2Subject"/> element.</param>
        /// <returns>An instance of <see cref="Saml2Subject"/> .</returns>
        /// <remarks>
        /// The default implementation does not handle the optional
        /// &lt;EncryptedID> element. To handle encryped IDs in the Subject,
        /// override this method.
        /// </remarks>
        protected virtual Saml2Subject ReadSubject(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Saml2Constants.Elements.Subject, Saml2Constants.Namespace);
            try
            {
                // @attributes

                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.SubjectType, Saml2Constants.Namespace);

                // <elements>
                Saml2Subject subject = new Saml2Subject();
                reader.Read();

                // <NameID> | <EncryptedID> | <BaseID> 0-1
                subject.NameId = ReadSubjectId(reader, Saml2Constants.Elements.Subject);

                // <SubjectConfirmation> 0-OO
                while (reader.IsStartElement(Saml2Constants.Elements.SubjectConfirmation, Saml2Constants.Namespace))
                {
                    subject.SubjectConfirmations.Add(ReadSubjectConfirmation(reader));
                }

                reader.ReadEndElement();

                // Must have a NameID or a SubjectConfirmation
                if (null == subject.NameId && 0 == subject.SubjectConfirmations.Count)
                    throw LogReadException(LogMessages.IDX11125);

                return subject;
            }
            catch (Exception ex)
            {
                if (ex is Saml2SecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.Subject, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;SubjectConfirmation> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2SubjectConfirmation"/> element.</param>
        /// <returns>An instance of <see cref="Saml2SubjectConfirmation"/> .</returns>
        protected virtual Saml2SubjectConfirmation ReadSubjectConfirmation(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Saml2Constants.Elements.SubjectConfirmation, Saml2Constants.Namespace);
            try
            {
                bool isEmpty = reader.IsEmptyElement;

                // @attributes

                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.SubjectConfirmationType, Saml2Constants.Namespace);

                // @Method - required
                string method = reader.GetAttribute(Saml2Constants.Attributes.Method);
                if (string.IsNullOrEmpty(method))
                    throw LogReadException(LogMessages.IDX11106, Saml2Constants.Elements.SubjectConfirmation, Saml2Constants.Attributes.Method);

                if (!CanCreateValidUri(method, UriKind.Absolute))
                    throw LogReadException(LogMessages.IDX11107, Saml2Constants.Types.SubjectConfirmationType, Saml2Constants.Attributes.Method, reader.LocalName);

                // Construct the appropriate SubjectConfirmation based on the method
                Saml2SubjectConfirmation subjectConfirmation = new Saml2SubjectConfirmation(new Uri(method));

                // <elements>
                reader.Read();
                if (!isEmpty)
                {
                    // <NameID> | <EncryptedID> | <BaseID> 0-1
                    subjectConfirmation.NameIdentifier = ReadSubjectId(reader, Saml2Constants.Elements.SubjectConfirmation);

                    // <SubjectConfirmationData> 0-1
                    if (reader.IsStartElement(Saml2Constants.Elements.SubjectConfirmationData, Saml2Constants.Namespace))
                        subjectConfirmation.SubjectConfirmationData = ReadSubjectConfirmationData(reader);

                    reader.ReadEndElement();
                }

                return subjectConfirmation;
            }
            catch (Exception ex)
            {
                if (ex is Saml2SecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.SubjectConfirmation, ex);
            }
        }

        /// <summary>
        /// Reads the &lt;saml:SubjectConfirmationData> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2SubjectConfirmationData"/> element.</param>
        /// <returns>An instance of <see cref="Saml2SubjectConfirmationData"/> .</returns>
        /// <remarks>
        /// The default implementation handles the unextended element
        /// as well as the extended type saml:KeyInfoConfirmationDataType.
        /// </remarks>
        protected virtual Saml2SubjectConfirmationData ReadSubjectConfirmationData(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Saml2Constants.Elements.SubjectConfirmationData, Saml2Constants.Namespace);
            try
            {
                Saml2SubjectConfirmationData confirmationData = new Saml2SubjectConfirmationData();
                bool isEmpty = reader.IsEmptyElement;

                // @attributes
                string value;

                // @xsi:type
                bool requireKeyInfo = false;
                XmlQualifiedName type = XmlUtil.GetXsiType(reader);

                if (null != type)
                {
                    if (XmlUtil.EqualsQName(type, Saml2Constants.Types.KeyInfoConfirmationDataType, Saml2Constants.Namespace))
                        requireKeyInfo = true;
                    else if (!XmlUtil.EqualsQName(type, Saml2Constants.Types.SubjectConfirmationDataType, Saml2Constants.Namespace))
                        throw LogReadException(LogMessages.IDX11126, type.Name, type.Namespace);
                }

                // KeyInfoConfirmationData cannot be empty
                if (requireKeyInfo && isEmpty)
                    throw LogReadException(LogMessages.IDX11127);

                // @Address - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.Address);
                if (!string.IsNullOrEmpty(value))
                {
                    confirmationData.Address = value;
                }

                // @InResponseTo - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.InResponseTo);
                if (!string.IsNullOrEmpty(value))
                {
                    confirmationData.InResponseTo = new Saml2Id(value);
                }

                // @NotBefore - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.NotBefore);
                if (!string.IsNullOrEmpty(value))
                {
                    confirmationData.NotBefore = XmlConvert.ToDateTime(value, XmlDateTimeSerializationMode.Utc);
                }

                // @NotOnOrAfter - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.NotOnOrAfter);
                if (!string.IsNullOrEmpty(value))
                {
                    confirmationData.NotOnOrAfter = XmlConvert.ToDateTime(value, XmlDateTimeSerializationMode.Utc);
                }

                // @Recipient - optional
                value = reader.GetAttribute(Saml2Constants.Attributes.Recipient);
                if (!string.IsNullOrEmpty(value))
                {
                    if (!CanCreateValidUri(value, UriKind.Absolute))
                        throw LogReadException(LogMessages.IDX11107, Saml2Constants.Elements.SubjectConfirmationData, Saml2Constants.Attributes.Recipient, reader.LocalName);

                    confirmationData.Recipient = new Uri(value);
                }

                // Contents
                reader.Read();

                if (!isEmpty)
                {
                    // <ds:KeyInfo> 0-OO OR 1-OO
                    if (requireKeyInfo)
                    {
                        var keyInfo = new KeyInfo();
                        keyInfo.ReadFrom(reader);
                        confirmationData.KeyInfos.Add(keyInfo);
                    }

                    while (reader.IsStartElement(XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace))
                    {
                        var keyInfo = new KeyInfo();
                        keyInfo.ReadFrom(reader);
                        confirmationData.KeyInfos.Add(keyInfo);
                    }

                    // If this isn't KeyInfo restricted, there might be open content here ...
                    if (!requireKeyInfo && XmlNodeType.EndElement != reader.NodeType)
                    {
                        // So throw and tell the user how to handle the open content
                        throw LogReadException(LogMessages.IDX11128, Saml2Constants.Elements.SubjectConfirmationData);
                    }

                    reader.ReadEndElement();
                }

                return confirmationData;
            }
            catch (Exception ex)
            {
                if (ex is Saml2SecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.SubjectConfirmationData, ex);
            }
        }

        /// <summary>
        /// Deserializes the SAML SubjectId.
        /// </summary>
        /// <param name="reader">XmlReader positioned at "NameID, EncryptedID, BaseID".</param>
        /// <param name="parentElement">the element name of the parent element. Used in exception string.</param>
        /// <exception cref="Saml2SecurityTokenReadException">if Element is 'BaseID' with no xsi type.</exception>
        /// <exception cref="Saml2SecurityTokenReadException">if reader is pointing at an unknown Element.</exception>
        /// <returns>A <see cref="Saml2NameIdentifier"/> instance.</returns>
        protected virtual Saml2NameIdentifier ReadSubjectId(XmlDictionaryReader reader, string parentElement)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            // <NameID>, <EncryptedID>, <BaseID>
            if (reader.IsStartElement(Saml2Constants.Elements.NameID, Saml2Constants.Namespace))
                return ReadNameId(reader);
            else if (reader.IsStartElement(Saml2Constants.Elements.EncryptedID, Saml2Constants.Namespace))
                return ReadEncryptedId(reader);
            else if (reader.IsStartElement(Saml2Constants.Elements.BaseID, Saml2Constants.Namespace))
            {
                // Since BaseID is an abstract type, we have to switch off the xsi:type declaration
                var declaredType = XmlUtil.GetXsiType(reader);

                // No declaration, or declaring that this is just a "BaseID", is invalid since statement is abstract
                if (null == declaredType
                    || XmlUtil.EqualsQName(declaredType, Saml2Constants.Types.BaseIDAbstractType, Saml2Constants.Namespace))
                    throw LogReadException(LogMessages.IDX11103, Saml2Constants.Elements.BaseID, declaredType, GetType(), "ReadSubjectId" );

                // If it's NameID we can handle it
                if (XmlUtil.EqualsQName(declaredType, Saml2Constants.Types.NameIDType, Saml2Constants.Namespace))
                    return ReadNameIdType(reader);
                else
                    // Instruct the user to override to handle custom <BaseID>
                    throw LogReadException(LogMessages.IDX11103, Saml2Constants.Elements.BaseID, declaredType, GetType(), "ReadSubjectId");
            }

            throw LogReadException(LogMessages.IDX11103, parentElement, reader.Name, GetType(), "ReadSubjectId");
        }

        /// <summary>
        /// Reads the &lt;saml:SubjectLocality> element.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned at a <see cref="Saml2SubjectLocality"/> element.</param>
        /// <returns>An instance of <see cref="Saml2SubjectLocality"/> .</returns>
        protected virtual Saml2SubjectLocality ReadSubjectLocality(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, Saml2Constants.Elements.SubjectLocality, Saml2Constants.Namespace);
            try
            {
                var subjectLocality = new Saml2SubjectLocality();
                bool isEmpty = reader.IsEmptyElement;

                // @attributes

                // @xsi:type
                XmlUtil.ValidateXsiType(reader, Saml2Constants.Types.SubjectLocalityType, Saml2Constants.Namespace);

                // @Address - optional
                subjectLocality.Address = reader.GetAttribute(Saml2Constants.Attributes.Address);

                // @DNSName - optional
                subjectLocality.DnsName = reader.GetAttribute(Saml2Constants.Attributes.DNSName);

                // Empty content
                reader.Read();
                if (!isEmpty)
                {
                    reader.ReadEndElement();
                }

                return subjectLocality;
            }
            catch (Exception ex)
            {
                if (ex is Saml2SecurityTokenReadException)
                    throw;

                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.SubjectLocality, ex);
            }
        }

        /// <summary>
        /// Writes the &lt;saml:Action> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2Action"/>.</param>
        /// <param name="action">The <see cref="Saml2Action"/> to serialize.</param>
        protected virtual void WriteAction(XmlWriter writer, Saml2Action action)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (action == null)
                throw LogHelper.LogArgumentNullException(nameof(action));

            if (null == action.Namespace)
                throw LogHelper.LogArgumentNullException(nameof(action.Namespace));

            if (string.IsNullOrEmpty(action.Namespace.ToString()))
                throw LogHelper.LogArgumentNullException("action.Namespace");

            // <Action>
            writer.WriteStartElement(Saml2Constants.Elements.Action, Saml2Constants.Namespace);

            // @Namespace - required
            writer.WriteAttributeString(Saml2Constants.Attributes.Namespace, action.Namespace.OriginalString);

            // String content
            writer.WriteString(action.Value);

            // </Action>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the &lt;saml:Advice> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2Advice"/>.</param>
        /// <param name="advice">The <see cref="Saml2Advice"/> to serialize.</param>
        protected virtual void WriteAdvice(XmlWriter writer, Saml2Advice advice)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (null == advice)
                throw LogHelper.LogArgumentNullException(nameof(advice));

            // <Advice>
            writer.WriteStartElement(Saml2Constants.Elements.Advice, Saml2Constants.Namespace);

            // <AssertionIDRef> 0-OO
            foreach (Saml2Id id in advice.AssertionIdReferences)
                writer.WriteElementString(Saml2Constants.Elements.AssertionIDRef, Saml2Constants.Namespace, id.Value);

            // <AssertionURIRef> 0-OO
            foreach (Uri uri in advice.AssertionUriReferences)
                writer.WriteElementString(Saml2Constants.Elements.AssertionURIRef, Saml2Constants.Namespace, uri.OriginalString);

            // <Assertion> 0-OO
            foreach (Saml2Assertion assertion in advice.Assertions)
                WriteAssertion(writer, assertion);

            // </Advice>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Serializes the provided SamlAssertion to the XmlWriter.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2Assertion"/>.</param>
        /// <param name="assertion">The <see cref="Saml2Assertion"/> to serialize.</param>
        /// <exception cref="ArgumentNullException">The <paramref name="writer"/> or <paramref name="assertion"/> parameters are null.</exception>
        /// <exception cref="InvalidOperationException">The <paramref name="assertion"/> must have a <see cref="Saml2Subject"/> if no <see cref="Saml2Statement"/> are present.</exception>
        /// <exception cref="InvalidOperationException">The SAML2 authentication, attribute, and authorization decision <see cref="Saml2Statement"/> require a <see cref="Saml2Subject"/>.</exception>
        public virtual void WriteAssertion(XmlWriter writer, Saml2Assertion assertion)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (assertion == null)
                throw LogHelper.LogArgumentNullException(nameof(assertion));

            if (assertion.EncryptingCredentials != null)
                throw LogHelper.LogExceptionMessage(new NotSupportedException("Encryption not supported."));

            // If we've saved off the token stream, re-emit it.
            if (assertion.CanWriteSourceData)
                assertion.WriteSourceData(writer);
            else
            {
                // Wrap the writer if necessary for a signature
                // We do not dispose this writer, since as a delegating writer it would
                // dispose the inner writer, which we don't properly own.
                EnvelopedSignatureWriter signatureWriter = null;
                if (null != assertion.SigningCredentials)
                    writer = signatureWriter = new EnvelopedSignatureWriter(writer, assertion.SigningCredentials, assertion.Id.Value);

                if (null == assertion.Subject)
                {
                    // An assertion with no statements MUST contain a <Subject> element. [Saml2Core, line 585]
                    if (assertion.Statements == null || 0 == assertion.Statements.Count)
                    {
                        throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException("no subject and no statements, not allowed"));
                    }

                    // Furthermore, the built-in statement types all require the presence of a subject.
                    // [Saml2Core, lines 1050, 1168, 1280]
                    foreach (Saml2Statement statement in assertion.Statements)
                    {
                        if (statement is Saml2AuthenticationStatement
                            || statement is Saml2AttributeStatement
                            || statement is Saml2AuthorizationDecisionStatement)
                        {
                            throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException("unknown statement type"));
                        }
                    }
                }

                // <Assertion>
                writer.WriteStartElement(Saml2Constants.Elements.Assertion, Saml2Constants.Namespace);

                // @ID - required
                writer.WriteAttributeString(Saml2Constants.Attributes.ID, assertion.Id.Value);

                // @IssueInstant - required
                writer.WriteAttributeString(Saml2Constants.Attributes.IssueInstant, XmlConvert.ToString(assertion.IssueInstant.ToUniversalTime(), Saml2Constants.GeneratedDateTimeFormat));

                // @Version - required
                writer.WriteAttributeString(Saml2Constants.Attributes.Version, assertion.Version);

                // <Issuer> 1
                WriteIssuer(writer, assertion.Issuer);

                // <ds:Signature> 0-1
                if (null != signatureWriter)
                    signatureWriter.WriteSignature();

                // <Subject> 0-1
                if (null != assertion.Subject)
                    WriteSubject(writer, assertion.Subject);

                // <Conditions> 0-1
                if (null != assertion.Conditions)
                    WriteConditions(writer, assertion.Conditions);

                // <Advice> 0-1
                if (null != assertion.Advice)
                    WriteAdvice(writer, assertion.Advice);

                // <Statement|AuthnStatement|AuthzDecisionStatement|AttributeStatement>, 0-OO
                foreach (Saml2Statement statement in assertion.Statements)
                    WriteStatement(writer, statement);

                writer.WriteEndElement();
            }
        }

        /// <summary>
        /// Writes the &lt;saml:Attribute> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2Attribute"/>.</param>
        /// <param name="attribute">The <see cref="Saml2Attribute"/> to serialize.</param>
        public virtual void WriteAttribute(XmlWriter writer, Saml2Attribute attribute)
        {
            // TODO = temporarily public until actor is processing is complete
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (null == attribute)
                throw LogHelper.LogArgumentNullException(nameof(attribute));

            // <Attribute>
            writer.WriteStartElement(Saml2Constants.Elements.Attribute, Saml2Constants.Namespace);

            // @Name - required
            writer.WriteAttributeString(Saml2Constants.Attributes.Name, attribute.Name);

            // @NameFormat - optional
            if (null != attribute.NameFormat)
                writer.WriteAttributeString(Saml2Constants.Attributes.NameFormat, attribute.NameFormat.OriginalString);

            // @FriendlyName - optional
            if (null != attribute.FriendlyName)
                writer.WriteAttributeString(Saml2Constants.Attributes.FriendlyName, attribute.FriendlyName);

            // @OriginalIssuer - optional
            if (null != attribute.OriginalIssuer)
                writer.WriteAttributeString(Saml2Constants.Attributes.OriginalIssuer, attribute.OriginalIssuer);

            string xsiTypePrefix = null;
            string xsiTypeSuffix = null;
            if (!StringComparer.Ordinal.Equals(attribute.AttributeValueXsiType, ClaimValueTypes.String))
            {
                // ClaimValueTypes are URIs of the form prefix#suffix, while xsi:type should be a QName.
                // Hence, the tokens-to-claims spec requires that ClaimValueTypes be serialized as xmlns:tn="prefix" xsi:type="tn:suffix"
                int indexOfHash = attribute.AttributeValueXsiType.IndexOf('#');
                xsiTypePrefix = attribute.AttributeValueXsiType.Substring(0, indexOfHash);
                xsiTypeSuffix = attribute.AttributeValueXsiType.Substring(indexOfHash + 1);
            }

            // <AttributeValue> 0-OO (nillable)
            foreach (string value in attribute.Values)
            {
                writer.WriteStartElement(Saml2Constants.Elements.AttributeValue, Saml2Constants.Namespace);

                if (null == value)
                {
                    writer.WriteAttributeString(XmlSignatureConstants.Attributes.Nil, XmlSignatureConstants.XmlSchemaNamespace, XmlConvert.ToString(true));
                }
                else if (value.Length > 0)
                {
                    if ((xsiTypePrefix != null) && (xsiTypeSuffix != null))
                    {
                        writer.WriteAttributeString(XmlSignatureConstants.XmlNamepspacePrefix, Saml2Constants.ClaimValueTypeSerializationPrefix, null, xsiTypePrefix);
                        writer.WriteAttributeString(XmlSignatureConstants.Attributes.Type, XmlSignatureConstants.XmlSchemaNamespace, string.Concat(Saml2Constants.ClaimValueTypeSerializationPrefixWithColon, xsiTypeSuffix));
                    }

                    WriteAttributeValue(writer, value, attribute);
                }

                writer.WriteEndElement();
            }

            // </Attribute>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the &lt;saml:AttributeStatement> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2AttributeStatement"/>.</param>
        /// <param name="attributeStatement">The <see cref="Saml2AttributeStatement"/> to serialize.</param>
        protected virtual void WriteAttributeStatement(XmlWriter writer, Saml2AttributeStatement attributeStatement)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));


            if (null == attributeStatement)
                throw LogHelper.LogArgumentNullException(nameof(attributeStatement));

            if (attributeStatement.Attributes == null || 0 == attributeStatement.Attributes.Count)
                throw LogWriteException(LogMessages.IDX11129);

            // <AttributeStatement>
            writer.WriteStartElement(Saml2Constants.Elements.AttributeStatement, Saml2Constants.Namespace);

            // <Attribute> 1-OO
            foreach (Saml2Attribute attribute in attributeStatement.Attributes)
                WriteAttribute(writer, attribute);

            // </AttributeStatement>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the saml:Attribute value.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2Attribute"/>.</param>
        /// <param name="value">The value of the attribute being serialized.</param>
        /// <param name="attribute">The <see cref="Saml2Attribute"/> to serialize.</param>
        /// <remarks>By default the method writes the value as a string.</remarks>
        /// <exception cref="ArgumentNullException">The input parameter 'writer' is null.</exception>
        protected virtual void WriteAttributeValue(XmlWriter writer, string value, Saml2Attribute attribute)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            writer.WriteString(value);
        }

        /// <summary>
        /// Writes the &lt;saml:AudienceRestriction> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2AudienceRestriction"/>.</param>
        /// <param name="audienceRestriction">The <see cref="Saml2AudienceRestriction"/> to serialize.</param>
        protected virtual void WriteAudienceRestriction(XmlWriter writer, Saml2AudienceRestriction audienceRestriction)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (audienceRestriction == null)
                throw LogHelper.LogArgumentNullException(nameof(audienceRestriction));

            // Schema requires at least one audience.
            if (audienceRestriction.Audiences == null || 0 == audienceRestriction.Audiences.Count)
                throw LogReadException(LogMessages.IDX11130);

            // <AudienceRestriction>
            writer.WriteStartElement(Saml2Constants.Elements.AudienceRestriction, Saml2Constants.Namespace);

            // <Audience> - 1-OO
            foreach (string audience in audienceRestriction.Audiences)
                writer.WriteElementString(Saml2Constants.Elements.Audience, Saml2Constants.Namespace, audience);

            // </AudienceRestriction>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the &lt;saml:AuthnContext> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2AuthenticationContext"/>.</param>
        /// <param name="authenticationContext">The <see cref="Saml2AuthenticationContext"/> to serialize.</param>
        protected virtual void WriteAuthenticationContext(XmlWriter writer, Saml2AuthenticationContext authenticationContext)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (authenticationContext == null)
                throw LogHelper.LogArgumentNullException(nameof(authenticationContext));

            // One of ClassRef and DeclRef must be present.
            if (authenticationContext.ClassReference == null && authenticationContext.DeclarationReference == null)
                throw LogWriteException(LogMessages.IDX11149);

            // <AuthnContext>
            writer.WriteStartElement(Saml2Constants.Elements.AuthnContext, Saml2Constants.Namespace);

            // <AuthnContextClassReference> 0-1
            if (authenticationContext.ClassReference != null)
                writer.WriteElementString(Saml2Constants.Elements.AuthnContextClassRef, Saml2Constants.Namespace, authenticationContext.ClassReference.OriginalString);

            // <AuthnContextDeclRef> 0-1
            if (authenticationContext.DeclarationReference != null)
                writer.WriteElementString(Saml2Constants.Elements.AuthnContextDeclRef, Saml2Constants.Namespace, authenticationContext.DeclarationReference.OriginalString);

            // <AuthenticatingAuthority> 0-OO
            foreach (var authority in authenticationContext.AuthenticatingAuthorities)
                writer.WriteElementString(Saml2Constants.Elements.AuthenticatingAuthority, Saml2Constants.Namespace, authority.OriginalString);

            // </AuthnContext>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the &lt;saml:AuthnStatement> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2AuthenticationStatement"/>.</param>
        /// <param name="authenticationStatement">The <see cref="Saml2AuthenticationStatement"/> to serialize.</param>
        protected virtual void WriteAuthenticationStatement(XmlWriter writer, Saml2AuthenticationStatement authenticationStatement)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (authenticationStatement == null)
                throw LogHelper.LogArgumentNullException(nameof(authenticationStatement));

            // <AuthnStatement>
            writer.WriteStartElement(Saml2Constants.Elements.AuthnStatement, Saml2Constants.Namespace);

            // @AuthnInstant - required
            writer.WriteAttributeString(Saml2Constants.Attributes.AuthnInstant, XmlConvert.ToString(authenticationStatement.AuthenticationInstant.ToUniversalTime(), Saml2Constants.GeneratedDateTimeFormat));

            // @SessionIndex - optional
            if (null != authenticationStatement.SessionIndex)
            {
                writer.WriteAttributeString(Saml2Constants.Attributes.SessionIndex, authenticationStatement.SessionIndex);
            }

            // @SessionNotOnOrAfter - optional
            if (null != authenticationStatement.SessionNotOnOrAfter)
                writer.WriteAttributeString(Saml2Constants.Attributes.SessionNotOnOrAfter, XmlConvert.ToString(authenticationStatement.SessionNotOnOrAfter.Value.ToUniversalTime(), Saml2Constants.GeneratedDateTimeFormat));

            // <SubjectLocality> 0-1
            if (null != authenticationStatement.SubjectLocality)
                WriteSubjectLocality(writer, authenticationStatement.SubjectLocality);

            // <AuthnContext> 1
            WriteAuthenticationContext(writer, authenticationStatement.AuthenticationContext);

            // </AuthnStatement>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the &lt;saml:AuthzDecisionStatement> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2AuthorizationDecisionStatement"/>.</param>
        /// <param name="authorizationDecisionStatement">The <see cref="Saml2AuthorizationDecisionStatement"/> to serialize.</param>
        protected virtual void WriteAuthorizationDecisionStatement(XmlWriter writer, Saml2AuthorizationDecisionStatement authorizationDecisionStatement)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (authorizationDecisionStatement == null)
                throw LogHelper.LogArgumentNullException(nameof(authorizationDecisionStatement));

            if (0 == authorizationDecisionStatement.Actions.Count)
            {
                throw LogHelper.LogExceptionMessage(
                    new Saml2SecurityTokenException("no actions specified ID4122"));
            }

            // <AuthzDecisionStatement>
            writer.WriteStartElement(Saml2Constants.Elements.AuthzDecisionStatement, Saml2Constants.Namespace);

            // @Decision - required
            writer.WriteAttributeString(Saml2Constants.Attributes.Decision, authorizationDecisionStatement.Decision.ToString());

            // @Resource - required
            writer.WriteAttributeString(Saml2Constants.Attributes.Resource, authorizationDecisionStatement.Resource.Equals(Saml2AuthorizationDecisionStatement.EmptyResource) ? authorizationDecisionStatement.Resource.ToString() : authorizationDecisionStatement.Resource.OriginalString);

            // @Action 1-OO
            foreach (Saml2Action action in authorizationDecisionStatement.Actions)
                WriteAction(writer, action);

            // Evidence 0-1
            if (null != authorizationDecisionStatement.Evidence)
                WriteEvidence(writer, authorizationDecisionStatement.Evidence);

            // </AuthzDecisionStatement>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the &lt;saml:Conditions> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2Conditions"/>.</param>
        /// <param name="conditions">The <see cref="Saml2Conditions"/> to serialize.</param>
        protected virtual void WriteConditions(XmlWriter writer, Saml2Conditions conditions)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (conditions == null)
                throw LogHelper.LogArgumentNullException(nameof(conditions));

            // <Conditions>
            writer.WriteStartElement(Saml2Constants.Elements.Conditions, Saml2Constants.Namespace);

            // @NotBefore - optional
            if (null != conditions.NotBefore)
                writer.WriteAttributeString(Saml2Constants.Attributes.NotBefore, XmlConvert.ToString(conditions.NotBefore.Value.ToUniversalTime(), Saml2Constants.GeneratedDateTimeFormat));


            // @NotOnOrAfter - optional
            if (null != conditions.NotOnOrAfter)
                writer.WriteAttributeString(Saml2Constants.Attributes.NotOnOrAfter, XmlConvert.ToString(conditions.NotOnOrAfter.Value.ToUniversalTime(), Saml2Constants.GeneratedDateTimeFormat));

            // <AudienceRestriction> 0-OO
            foreach (Saml2AudienceRestriction audienceRestriction in conditions.AudienceRestrictions)
                WriteAudienceRestriction(writer, audienceRestriction);

            // <OneTimeUse> - limited to one in SAML spec
            if (conditions.OneTimeUse)
            {
                writer.WriteStartElement(Saml2Constants.Elements.OneTimeUse, Saml2Constants.Namespace);
                writer.WriteEndElement();
            }

            // <ProxyRestriction> - limited to one in SAML spec
            if (null != conditions.ProxyRestriction)
                WriteProxyRestriction(writer, conditions.ProxyRestriction);

            // </Conditions>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the &lt;saml:Evidence> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2Evidence"/>.</param>
        /// <param name="evidence">The <see cref="Saml2Evidence"/> to serialize.</param>
        protected virtual void WriteEvidence(XmlWriter writer, Saml2Evidence evidence)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (evidence == null)
                throw LogHelper.LogArgumentNullException(nameof(evidence));

            if ((evidence.AssertionIdReferences == null || 0 == evidence.AssertionIdReferences.Count)
               && (evidence.Assertions == null || 0 == evidence.Assertions.Count)
               && (evidence.AssertionUriReferences == null || 0 == evidence.AssertionUriReferences.Count))
                throw LogWriteException(LogMessages.IDX11122);

            // <Evidence>
            writer.WriteStartElement(Saml2Constants.Elements.Evidence, Saml2Constants.Namespace);

            // <AssertionIDRef> 0-OO
            foreach (Saml2Id id in evidence.AssertionIdReferences)
                writer.WriteElementString(Saml2Constants.Elements.AssertionIDRef, Saml2Constants.Namespace, id.Value);

            // <AssertionURIRef> 0-OO
            foreach (Uri uri in evidence.AssertionUriReferences)
                writer.WriteElementString(Saml2Constants.Elements.AssertionURIRef, Saml2Constants.Namespace, uri.OriginalString);

            // <Assertion> 0-OO
            foreach (Saml2Assertion assertion in evidence.Assertions)
                WriteAssertion(writer, assertion);

            // </Evidence>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the &lt;saml:Issuer> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2NameIdentifier"/>.</param>
        /// <param name="nameIdentifier">The <see cref="Saml2NameIdentifier"/> to serialize.</param>
        protected virtual void WriteIssuer(XmlWriter writer, Saml2NameIdentifier nameIdentifier)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (nameIdentifier == null)
                throw LogHelper.LogArgumentNullException(nameof(nameIdentifier));

            writer.WriteStartElement(Saml2Constants.Elements.Issuer, Saml2Constants.Namespace);
            WriteNameIdType(writer, nameIdentifier);
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the &lt;saml:NameID> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2NameIdentifier"/>.</param>
        /// <param name="nameIdentifier">The <see cref="Saml2NameIdentifier"/> to serialize.</param>
        /// <exception cref="ArgumentNullException">If 'writer' is null.</exception>
        /// <exception cref="ArgumentNullException">If 'nameIdentifier' null.</exception>
        protected virtual void WriteNameId(XmlWriter writer, Saml2NameIdentifier nameIdentifier)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (null == nameIdentifier)
                throw LogHelper.LogArgumentNullException(nameof(nameIdentifier));

            if (nameIdentifier.EncryptingCredentials != null)
                throw LogHelper.LogExceptionMessage(new NotSupportedException("Encryption not supported."));

            writer.WriteStartElement(Saml2Constants.Elements.NameID, Saml2Constants.Namespace);
            this.WriteNameIdType(writer, nameIdentifier);
            writer.WriteEndElement();
        }

        /// <summary>
        /// Both &lt;Issuer> and &lt;NameID> are of NameIDType. Writes the content of either one of those elements.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2NameIdentifier"/>.</param>
        /// <param name="nameIdentifier">The <see cref="Saml2NameIdentifier"/> to serialize.</param>
        /// <exception cref="ArgumentNullException">If 'writer' is null.</exception>
        /// <exception cref="ArgumentNullException">If 'nameIdentifier' is null.</exception>
        /// <exception cref="ArgumentNullException">If 'nameIdentifier.Value' is null or empty.</exception>
        protected virtual void WriteNameIdType(XmlWriter writer, Saml2NameIdentifier nameIdentifier)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (nameIdentifier == null)
                throw LogHelper.LogArgumentNullException(nameof(nameIdentifier));

            if (string.IsNullOrEmpty(nameIdentifier.Value))
                throw LogHelper.LogArgumentNullException(LogHelper.FormatInvariant(LogMessages.IDX11151, Saml2Constants.Elements.NameID, "nameIdentifier.Value"));

            // @Format - optional
            if (null != nameIdentifier.Format)
                writer.WriteAttributeString(Saml2Constants.Attributes.Format, nameIdentifier.Format.OriginalString);

            // @NameQualifier - optional
            if (!string.IsNullOrEmpty(nameIdentifier.NameQualifier))
                writer.WriteAttributeString(Saml2Constants.Attributes.NameQualifier, nameIdentifier.NameQualifier);

            // @SPNameQualifier - optional
            if (!string.IsNullOrEmpty(nameIdentifier.SPNameQualifier))
                writer.WriteAttributeString(Saml2Constants.Attributes.SPNameQualifier, nameIdentifier.SPNameQualifier);

            // @SPProvidedId - optional
            if (!string.IsNullOrEmpty(nameIdentifier.SPProvidedId))
                writer.WriteAttributeString(Saml2Constants.Attributes.SPProvidedID, nameIdentifier.SPProvidedId);

            // Content is string
            writer.WriteString(nameIdentifier.Value);
        }

        /// <summary>
        /// Writes the &lt;saml:ProxyRestriction> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2ProxyRestriction"/>.</param>
        /// <param name="proxyRestriction">The <see cref="Saml2ProxyRestriction"/> to serialize.</param>
        protected virtual void WriteProxyRestriction(XmlWriter writer, Saml2ProxyRestriction proxyRestriction)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (proxyRestriction == null)
                throw LogHelper.LogArgumentNullException(nameof(proxyRestriction));

            writer.WriteStartElement(Saml2Constants.Elements.ProxyRestricton, Saml2Constants.Namespace);

            // @Count - optional
            if (proxyRestriction.Count != null)
                writer.WriteAttributeString(Saml2Constants.Attributes.Count, XmlConvert.ToString(proxyRestriction.Count.Value));

            // <Audience> - 0-OO
            foreach (Uri uri in proxyRestriction.Audiences)
                writer.WriteElementString(Saml2Constants.Elements.Audience, uri.OriginalString);

            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes a Saml2Statement.
        /// </summary>
        /// <remarks>
        /// This method may write a &lt;saml:AttributeStatement>, &lt;saml:AuthnStatement>
        /// or &lt;saml:AuthzDecisionStatement> element. To handle custom Saml2Statement
        /// classes for writing a &lt;saml:Statement> element, override this method.
        /// </remarks>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2Statement"/>.</param>
        /// <param name="statement">The <see cref="Saml2Statement"/> to serialize.</param>
        protected virtual void WriteStatement(XmlWriter writer, Saml2Statement statement)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (statement == null)
                throw LogHelper.LogArgumentNullException(nameof(statement));

            Saml2AttributeStatement attributeStatement = statement as Saml2AttributeStatement;
            if (null != attributeStatement)
            {
                WriteAttributeStatement(writer, attributeStatement);
                return;
            }

            Saml2AuthenticationStatement authnStatement = statement as Saml2AuthenticationStatement;
            if (null != authnStatement)
            {
                WriteAuthenticationStatement(writer, authnStatement);
                return;
            }

            Saml2AuthorizationDecisionStatement authzStatement = statement as Saml2AuthorizationDecisionStatement;
            if (null != authzStatement)
            {
                WriteAuthorizationDecisionStatement(writer, authzStatement);
                return;
            }

            throw LogWriteException(LogMessages.IDX11133);
        }

        /// <summary>
        /// Writes the &lt;saml:Subject> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2Subject"/>.</param>
        /// <param name="subject">The <see cref="Saml2Subject"/> to serialize.</param>
        protected virtual void WriteSubject(XmlWriter writer, Saml2Subject subject)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (subject == null)
                throw LogHelper.LogArgumentNullException(nameof(subject));

            // If there's no ID, there has to be a SubjectConfirmation
            if (null == subject.NameId && 0 == subject.SubjectConfirmations.Count)
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException("both id and subjectconfirmation cannot be null"));

            // <Subject>
            writer.WriteStartElement(Saml2Constants.Elements.Subject, Saml2Constants.Namespace);

            // no attributes

            // <NameID> 0-1
            if (null != subject.NameId)
                WriteNameId(writer, subject.NameId);

            // <SubjectConfirmation> 0-OO
            foreach (Saml2SubjectConfirmation subjectConfirmation in subject.SubjectConfirmations)
                WriteSubjectConfirmation(writer, subjectConfirmation);

            // </Subject>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the &lt;saml:SubjectConfirmation> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2SubjectConfirmation"/>.</param>
        /// <param name="subjectConfirmation">The <see cref="Saml2SubjectConfirmation"/> to serialize.</param>
        protected virtual void WriteSubjectConfirmation(XmlWriter writer, Saml2SubjectConfirmation subjectConfirmation)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (subjectConfirmation == null)
                throw LogHelper.LogArgumentNullException(nameof(subjectConfirmation));

            if (subjectConfirmation.Method == null)
                throw LogHelper.LogArgumentNullException(nameof(subjectConfirmation.Method));

            if (string.IsNullOrEmpty(subjectConfirmation.Method.OriginalString))
                throw LogHelper.LogArgumentNullException(nameof(subjectConfirmation.Method.OriginalString));

            // <SubjectConfirmation>
            writer.WriteStartElement(Saml2Constants.Elements.SubjectConfirmation, Saml2Constants.Namespace);

            // @Method - required
            writer.WriteAttributeString(Saml2Constants.Attributes.Method, subjectConfirmation.Method.OriginalString);

            // <NameID> 0-1
            if (null != subjectConfirmation.NameIdentifier)
                WriteNameId(writer, subjectConfirmation.NameIdentifier);

            // <SubjectConfirmationData> 0-1
            if (null != subjectConfirmation.SubjectConfirmationData)
                WriteSubjectConfirmationData(writer, subjectConfirmation.SubjectConfirmationData);

            // </SubjectConfirmation>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the &lt;saml:SubjectConfirmationData> element.
        /// </summary>
        /// <remarks>
        /// When the data.KeyIdentifiers collection is not empty, an xsi:type
        /// attribute will be written specifying saml:KeyInfoConfirmationDataType.
        /// </remarks>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2SubjectConfirmationData"/>.</param>
        /// <param name="subjectConfirmationData">The <see cref="Saml2SubjectConfirmationData"/> to serialize.</param>
        protected virtual void WriteSubjectConfirmationData(XmlWriter writer, Saml2SubjectConfirmationData subjectConfirmationData)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (subjectConfirmationData == null)
                throw LogHelper.LogArgumentNullException(nameof(subjectConfirmationData));

            // <SubjectConfirmationData>
            writer.WriteStartElement(Saml2Constants.Elements.SubjectConfirmationData, Saml2Constants.Namespace);

            // @attributes

            // @xsi:type
            if (subjectConfirmationData.KeyInfos.Count > 0)
                writer.WriteAttributeString(XmlSignatureConstants.Attributes.Type, XmlSignatureConstants.XmlSchemaNamespace, Saml2Constants.Types.KeyInfoConfirmationDataType);

            // @Address - optional
            if (!string.IsNullOrEmpty(subjectConfirmationData.Address))
                writer.WriteAttributeString(Saml2Constants.Attributes.Address, subjectConfirmationData.Address);

            // @InResponseTo - optional
            if (null != subjectConfirmationData.InResponseTo)
                writer.WriteAttributeString(Saml2Constants.Attributes.InResponseTo, subjectConfirmationData.InResponseTo.Value);

            // @NotBefore - optional
            if (null != subjectConfirmationData.NotBefore)
                writer.WriteAttributeString(Saml2Constants.Attributes.NotBefore, XmlConvert.ToString(subjectConfirmationData.NotBefore.Value.ToUniversalTime(), Saml2Constants.GeneratedDateTimeFormat));

            // @NotOnOrAfter - optional
            if (null != subjectConfirmationData.NotOnOrAfter)
                writer.WriteAttributeString(Saml2Constants.Attributes.NotOnOrAfter, XmlConvert.ToString(subjectConfirmationData.NotOnOrAfter.Value.ToUniversalTime(), Saml2Constants.GeneratedDateTimeFormat));

            // @Recipient - optional
            if (null != subjectConfirmationData.Recipient)
                writer.WriteAttributeString(Saml2Constants.Attributes.Recipient, subjectConfirmationData.Recipient.OriginalString);

            // Content

            // <ds:KeyInfo> 0-OO
            foreach (var keyInfo in subjectConfirmationData.KeyInfos)
                keyInfo.WriteTo(writer);

            // </SubjectConfirmationData>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the &lt;saml:SubjectLocality> element.
        /// </summary>
        /// <param name="writer">A <see cref="XmlWriter"/> to serialize the <see cref="Saml2SubjectLocality"/>.</param>
        /// <param name="subjectLocality">The <see cref="Saml2SubjectLocality"/> to serialize.</param>
        protected virtual void WriteSubjectLocality(XmlWriter writer, Saml2SubjectLocality subjectLocality)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            if (subjectLocality == null)
                throw LogHelper.LogArgumentNullException(nameof(subjectLocality));

            // <SubjectLocality>
            writer.WriteStartElement(Saml2Constants.Elements.SubjectLocality, Saml2Constants.Namespace);

            // @Address - optional
            if (null != subjectLocality.Address)
            {
                writer.WriteAttributeString(Saml2Constants.Attributes.Address, subjectLocality.Address);
            }

            // @DNSName - optional
            if (null != subjectLocality.DnsName)
            {
                writer.WriteAttributeString(Saml2Constants.Attributes.DNSName, subjectLocality.DnsName);
            }

            // </SubjectLocality>
            writer.WriteEndElement();
        }

        internal static void ReadEmptyContentElement(XmlDictionaryReader reader)
        {
            bool isEmpty = reader.IsEmptyElement;
            reader.Read();
            if (!isEmpty)
            {
                reader.ReadEndElement();
            }
        }

        internal static Saml2Id ReadSimpleNCNameElement(XmlDictionaryReader reader, string name)
        {
            try
            {
                if (reader.IsEmptyElement)
                    throw LogReadException(LogMessages.IDX11104, name);

                XmlUtil.ValidateXsiType(reader, XmlSignatureConstants.Attributes.NcName, XmlSignatureConstants.XmlSchemaNamespace);

                reader.MoveToElement();
                string value = reader.ReadElementContentAsString();

                return new Saml2Id(value);
            }
            catch (Exception ex)
            {
                throw LogReadException(LogMessages.IDX11102, ex, Saml2Constants.Elements.NameID, ex);
            }
        }

        // allow lax reading of relative URIs in some instances for interop
        internal static Uri ReadSimpleUriElement(XmlDictionaryReader reader, string element, UriKind kind, bool requireUri)
        {
            try
            {
                if (reader.IsEmptyElement)
                    throw LogReadException(LogMessages.IDX11104, "Uri");

                XmlUtil.ValidateXsiType(reader, XmlSignatureConstants.Attributes.AnyUri, XmlSignatureConstants.XmlSchemaNamespace);
                reader.MoveToElement();
                string value = reader.ReadElementContentAsString();

                if (string.IsNullOrEmpty(value))
                    throw LogReadException(LogMessages.IDX11136, element);

                // TODO - kind can change.
                if (requireUri && !CanCreateValidUri(value, kind))
                    throw LogReadException(LogMessages.IDX11107, element, value);

                return new Uri(value, kind);
            }
            catch (Exception ex)
            {
                throw LogReadException(LogMessages.IDX11102, ex, element, ex);
            }
        }

        internal static Exception LogReadException(string message)
        {
            return LogHelper.LogExceptionMessage(new Saml2SecurityTokenReadException(message));
        }

        internal static Exception LogReadException(string message, Exception ex)
        {
            return LogHelper.LogExceptionMessage(new Saml2SecurityTokenReadException(message, ex));
        }

        internal static Exception LogReadException(string format, params object[] args)
        {
            return LogHelper.LogExceptionMessage(new Saml2SecurityTokenReadException(LogHelper.FormatInvariant(format, args)));
        }

        internal static Exception LogReadException(string format, Exception inner, params object[] args)
        {
            return LogHelper.LogExceptionMessage(new Saml2SecurityTokenReadException(LogHelper.FormatInvariant(format, args), inner));
        }

        internal static Exception LogWriteException(string message)
        {
            return LogHelper.LogExceptionMessage(new Saml2SecurityTokenWriteException(message));
        }

        internal static Exception LogWriteException(string message, Exception ex)
        {
            return LogHelper.LogExceptionMessage(new Saml2SecurityTokenWriteException(message, ex));
        }

        internal static Exception LogWriteException(string format, params object[] args)
        {
            return LogHelper.LogExceptionMessage(new Saml2SecurityTokenWriteException(LogHelper.FormatInvariant(format, args)));
        }

        internal static Exception LogWriteException(string format, Exception inner, params object[] args)
        {
            return LogHelper.LogExceptionMessage(new Saml2SecurityTokenWriteException(LogHelper.FormatInvariant(format, args), inner));
        }
    }
}
