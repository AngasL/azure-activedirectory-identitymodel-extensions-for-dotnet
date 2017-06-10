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
using System.Collections.Generic;
using Microsoft.IdentityModel.Protocols.WsFederation;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Tests
{
    public static class Comparer
    {
        public static void GetDiffs(KeyInfo keyInfo1, KeyInfo keyInfo2,  List<string> diffs)
        {
            if (keyInfo1 == null && keyInfo2 == null)
                return;

            if (keyInfo1 == null && keyInfo2 != null)
                diffs.Add($" keyInfo1 == null && keyInfo2 != null");

            if (keyInfo1 != null && keyInfo2 == null)
                diffs.Add($" keyInfo1 != null && reference2 == null");

            string retVal = string.Empty;
            if (!IdentityComparer.AreStringsEqual(keyInfo1.CertificateData, keyInfo2.CertificateData))
                diffs.Add($" KeyInfo.CertificateData: {keyInfo1.CertificateData}, {keyInfo2.CertificateData}");

            if (!IdentityComparer.AreStringsEqual(keyInfo1.IssuerName, keyInfo2.IssuerName))
                diffs.Add($" KeyInfo.IssuerName: {keyInfo1.IssuerName}, {keyInfo2.IssuerName}");

            if (!IdentityComparer.AreStringsEqual(keyInfo1.Kid, keyInfo2.Kid))
                diffs.Add($" KeyInfo.Kid: {keyInfo1.Kid}, {keyInfo2.Kid}");

            if (!IdentityComparer.AreStringsEqual(keyInfo1.RetrievalMethodUri, keyInfo2.RetrievalMethodUri))
                diffs.Add($" KeyInfo.RetrievalMethodUri: {keyInfo1.RetrievalMethodUri}, {keyInfo2.RetrievalMethodUri}");

            if (!IdentityComparer.AreStringsEqual(keyInfo1.SerialNumber, keyInfo2.SerialNumber))
                diffs.Add($" KeyInfo.SerialNumber: '{keyInfo1.SerialNumber}', '{keyInfo2.SerialNumber}'");

            if (!IdentityComparer.AreStringsEqual(keyInfo1.SKI, keyInfo2.SKI))
                diffs.Add($" KeyInfo.SKI: {keyInfo1.SKI}, {keyInfo2.SKI}");

            if (!IdentityComparer.AreStringsEqual(keyInfo1.SubjectName, keyInfo2.SubjectName))
                diffs.Add($" KeyInfo.SubjectName: {keyInfo1.SubjectName}, {keyInfo2.SubjectName}");
        }

        public static void GetDiffs(Reference reference1, Reference reference2, List<string> diffs)
        {
            if (reference1 == null && reference2 == null)
                return;

            if (reference1 == null && reference2 != null)
                diffs.Add($" reference1 == null && reference2 != null");

            if (reference1 != null && reference2 == null)
                diffs.Add($" reference1 != null && reference2 == null");

            if (!IdentityComparer.AreStringsEqual(reference1.DigestAlgorithm, reference2.DigestAlgorithm))
                diffs.Add($" Reference.DigestAlgorithm: {reference1.DigestAlgorithm}, {reference2.DigestAlgorithm}");

            if (!IdentityComparer.AreStringsEqual(reference1.Uri, reference2.Uri))
                diffs.Add($" Reference.Uri: {reference1.Uri}, {reference2.Uri}");

            if (reference1.TransformChain.TransformCount != reference2.TransformChain.TransformCount)
                    diffs.Add($" Reference.TransformChain.TransformCount: {reference1.TransformChain.TransformCount}, {reference2.TransformChain.TransformCount}");
            else if (reference1.TransformChain.TransformCount > 0)
            {
                for (int i = 0; i < reference1.TransformChain.TransformCount; i++)
                {
                    if (reference1.TransformChain[i].GetType() != reference2.TransformChain[i].GetType())
                        diffs.Add($" Reference.TransformChain[{i}].GetType(): {reference1.TransformChain[i].GetType()} : {reference2.TransformChain[i].GetType()}");
                }
            }
        }

        public static void GetDiffs(Signature signature1, Signature signature2, List<string> diffs)
        {
            if (signature1 == null && signature2 == null)
                return;

            if (signature1 == null && signature2 != null)
                diffs.Add($" signature1 == null && signature2 != null");

            if (signature1 != null && signature2 == null)
                diffs.Add($" signature1 != null && signature2 == null");

            if (!IdentityComparer.AreStringsEqual(signature1.Id, signature2.Id))
                diffs.Add($" signature.Id: {signature1.Id}, {signature2.Id}");

            GetDiffs(signature1.KeyInfo, signature2.KeyInfo, diffs);
            GetDiffs(signature1.SignedInfo, signature2.SignedInfo, diffs);
        }

        public static void GetDiffs(SignedInfo signedInfo1, SignedInfo signedInfo2, List<string> diffs)
        {
            if (signedInfo1 == null && signedInfo2 == null)
                return;

            if (signedInfo1 == null && signedInfo2 != null)
                diffs.Add($" signedInfo1 == null && signedInfo2 != null");

            if (signedInfo1 != null && signedInfo2 == null)
                diffs.Add($" signedInfo1 != null && signedInfo2 == null");

            if (!IdentityComparer.AreStringsEqual(signedInfo1.CanonicalizationMethod, signedInfo2.CanonicalizationMethod))
                diffs.Add($" SignedInfo.CanonicalizationMethod: {signedInfo1.CanonicalizationMethod}, {signedInfo2.CanonicalizationMethod}");

            if (!IdentityComparer.AreStringsEqual(signedInfo1.SignatureAlgorithm, signedInfo2.SignatureAlgorithm))
                diffs.Add($" SignedInfo.SignatureAlgorithm: {signedInfo1.SignatureAlgorithm}, {signedInfo2.SignatureAlgorithm}");

            GetDiffs(signedInfo1.Reference, signedInfo2.Reference, diffs);
        }

        public static void GetDiffs(WsFederationConfiguration configuration1, WsFederationConfiguration configuration2, List<string> diffs)
        {
            if (configuration1 == null && configuration2 == null)
                return;

            if (configuration1 == null && configuration2 != null)
            {
                diffs.Add($" configuration1 == null && configuration2 != null");
                return;
            }

            if (configuration1 != null && configuration2 == null)
            {
                diffs.Add($" configuration1 != null && configuration2 == null");
                return;
            }

            var stringComparer = StringComparer.Ordinal;

            if (!stringComparer.Equals(configuration1.Issuer, configuration2.Issuer))
                diffs.Add($" WsFederationConfiguration.Issuer: {configuration1.Issuer}, {configuration2.Issuer}");

            if (!stringComparer.Equals(configuration1.TokenEndpoint, configuration2.TokenEndpoint))
                diffs.Add($" WsFederationConfiguration.TokenEndpoint: {configuration1.TokenEndpoint}, {configuration2.TokenEndpoint}");

            if (configuration1.KeyInfos.Count != configuration2.KeyInfos.Count)
                diffs.Add($" WsFederationConfiguration.KeyInfos.Count: {configuration1.KeyInfos.Count}, {configuration2.KeyInfos.Count}");
        }

        public static void GetDiffs(WsFederationMessage message1, WsFederationMessage message2, List<string> diffs)
        {
            if (message1 == null && message2 == null)
                return;

            if (message1 == null && message2 != null)
            {
                diffs.Add($" message1 == null && message2 != null");
                return;
            }

            if (message1 != null && message2 == null)
            {
                diffs.Add($" message1 != null && message2 == null");
                return;
            }

            if (message1.Parameters.Count != message2.Parameters.Count)
            {
                diffs.Add($" message1.Parameters.Count != message2.Parameters.Count: {message1.Parameters.Count}, {message2.Parameters.Count}");
            }

            var stringComparer = StringComparer.Ordinal;

            if (message1.IsSignInMessage != message2.IsSignInMessage)
                diffs.Add($" WsFederationMessage.IsSignInMessage: {message1.IsSignInMessage}, {message2.IsSignInMessage}");

            foreach (var param in message1.Parameters)
            {
                string value2;
                if (!message2.Parameters.TryGetValue(param.Key, out value2))
                    diffs.Add($" WsFederationMessage.message1.Parameters.param.Key missing in message2: {param.Key}");
                else if (param.Value != value2)
                    diffs.Add($" WsFederationMessage.message1.Parameters.param.Value !=  message2.Parameters.param.Value: {param.Key}, {param.Value}, {value2}");
            }

            foreach (var param in message2.Parameters)
            {
                string value1;
                if (!message1.Parameters.TryGetValue(param.Key, out value1))
                    diffs.Add($" WsFederationMessage.message2.Parameters.param.Key missing in message1: {param.Key}");
                else if (param.Value != value1)
                    diffs.Add($" WsFederationMessage.message2.Parameters.param.Value !=  message1.Parameters.param.Value: {param.Key}, {param.Value}, {value1}");
            }
        }

        public static void GetDiffs(SamlSecurityToken saml1, SamlSecurityToken saml2, List<string> diffs)
        {
            if (saml1 == null && saml2 == null)
                return;

            if (saml1 == null && saml2 != null)
            {
                diffs.Add($" saml1 == null && saml2 != null");
                return;
            }

            if (saml1 != null && saml2 == null)
            {
                diffs.Add($" saml1 != null && saml2 == null");
                return;
            }

            GetDiffs(saml1.Assertion, saml2.Assertion, diffs);
        }

        public static void GetDiffs(SamlAssertion assertion1, SamlAssertion assertion2, List<string> diffs)
        {
            if (assertion1 == null && assertion2 == null)
                return;

            if (assertion1 == null && assertion2 != null)
            {
                diffs.Add($" assertion1 == null && saml2 != null");
                return;
            }

            if (assertion1 != null && assertion2 == null)
            {
                diffs.Add($" assertion1 != null && assertion2 == null");
                return;
            }

            var stringComparer = StringComparer.Ordinal;

            if (!stringComparer.Equals(assertion1.AssertionId, assertion2.AssertionId))
                diffs.Add($" SamlAssertion.AssertionId: {assertion1.AssertionId}, {assertion2.AssertionId}");

            if (!DateTime.Equals(assertion1.IssueInstant, assertion2.IssueInstant))
                diffs.Add($" SamlAssertion.IssueInstant: {assertion1.IssueInstant}, {assertion2.IssueInstant}");

            if (!stringComparer.Equals(assertion1.Issuer, assertion2.Issuer))
                diffs.Add($" SamlAssertion.Issuer: {assertion1.Issuer}, {assertion2.Issuer}");

            if (assertion1.MajorVersion != assertion2.MajorVersion)
                diffs.Add($" SamlAssertion.MajorVersion: {assertion1.MajorVersion}, {assertion2.MajorVersion}");

            if (assertion1.MinorVersion != assertion2.MinorVersion)
                diffs.Add($" SamlAssertion.MinorVersion: {assertion1.MinorVersion}, {assertion2.MinorVersion}");

            GetDiffs(assertion1.Advice, assertion2.Advice, diffs);
            GetDiffs(assertion1.Conditions, assertion2.Conditions, diffs);
        }

        public static void GetDiffs(SamlAdvice advice1, SamlAdvice advice2, List<string> diffs)
        {
            if (advice1 == null && advice2 == null)
                return;

            if (advice1 == null && advice2 != null)
            {
                diffs.Add($" advice1 == null && advice2 != null");
                return;
            }

            if (advice1 != null && advice2 == null)
            {
                diffs.Add($" advice1 != null && advice2 == null");
                return;
            }

            if (advice1.AssertionIdReferences.Count != advice2.AssertionIdReferences.Count)
                diffs.Add($" SamlAdvice.AssertionIdReferences.Count: {advice1.AssertionIdReferences.Count}, {advice2.AssertionIdReferences.Count}");

            if (advice1.Assertions.Count != advice2.Assertions.Count)
                diffs.Add($" SamlAdvice.Assertions.Count: {advice1.Assertions.Count}, {advice2.Assertions.Count}");

            foreach (var idReference in advice1.AssertionIdReferences)
            {
                if (!advice2.AssertionIdReferences.Contains(idReference))
                    diffs.Add($" {idReference} in Advice.AssertionIdReferences missing in advice2.AssertionIdReferences.");
            }

            foreach (var idReference in advice2.AssertionIdReferences)
            {
                if (!advice1.AssertionIdReferences.Contains(idReference))
                    diffs.Add($" {idReference} in Advice.AssertionIdReferences missing in advice1.AssertionIdReferences.");
            }

            foreach (var assertion in advice1.Assertions)
            {
                if (!advice2.Assertions.Contains(assertion))
                    diffs.Add($" {assertion} in Advice.Assertions missing in advice2.Assertions.");
            }

            foreach (var assertion in advice2.Assertions)
            {
                if (!advice1.Assertions.Contains(assertion))
                    diffs.Add($" {assertion} in Advice.Assertions missing in advice1.Assertions.");
            }
        }

        public static void GetDiffs(SamlConditions conditions1, SamlConditions conditions2, List<string> diffs)
        { }

    }
}
